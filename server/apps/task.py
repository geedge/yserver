# 任务管理接口
import json
import uuid

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf
from sqlalchemy import and_

from exts import db
from model import Policy, TaskPolicy, Task, Agent
from sqlalchemy.exc import SQLAlchemyError
from .agentcomm import deliver_task
from .policy import *
from .util import da, error

bp = APIBlueprint("任务管理接口集合", __name__, url_prefix="/task")



class TaskSchema(Schema):
    id = String()
    target = String()
    name = String()
    agent = String()
    target_domain = String()
    target_rr = String()
    policy = String()
    create_time = DateTime()
    status = String(validate=OneOf(["working", "stop", "finish"]))


# 执行输出日志
class TaskLogSchema(Schema):
    # 输出时间
    time = DateTime()
    # 输出来源IP
    ip = String()
    # 该策略的目标IP
    targetip = String()
    # 日志等级
    level = String(validate=OneOf(["INFO", "WARNING", "ERROR"]))
    # 日志内容
    info = String()


# 任务状态时间轴信息
class TaskState(Schema):
    # 策略开始执行时间
    start_time = DateTime()
    # 策略名称
    policy_name = String()
    # 策略参数
    policy_param = String()
    # 执行策略编号
    policy_id = String()
    # 效果评估
    policy_status = String()


# 任务创建参数逻辑合法性检查
def valid_task_info(task_param: dict):
    if task_param["policy"] == "sjqp":
        if task_param["target_rr"] == "" or task_param["tdomain"] == "":
            return "数据欺骗缺乏目标域名或注入参数"
    return None


# 创建任务接口
@bp.post("/create")
@bp.doc("任务创建接口", "部分字段值的映射关系：</br>"
        + "policy 期望策略，可选参数范围及对应含义为：，auto-自动，ddos-拒绝服务，sjqp-数据欺骗</br>"
        + "scan 状态感知方式，可选参数范围及对应含义为：auto-自动，icmp-icmp/v6时延，tcp-tcp时延，dns-dns时延，record-记录正确性验证")
@bp.input({
    # 任务名称
    "name": String(),
    # 目标IP
    "target": IP(),
    # 执行代理
    "agent": String(),
    # 目标域名
    "target_domain": String(),
    # 期望注入记录
    "target_rr": String(),
    # 期望策略
    "policy": String(validate=OneOf(["auto", "ddos", "sjqp"])),
    # 状态感知方式
    "scan": String(validate=OneOf(["auto", "icmp", "dns", "tcp", "record"])),
    # 策略切换时限,单位分钟
    "policy_time": Integer(),
    # 任务执行时限，单位分钟
    "run_time": Integer(),
    # 运行配置
    "run_flag": String(validate=OneOf(["now", "man"]))
}, example={'name': "test_task", 'target': "1.2.3.4", 'agent': "8a9ces", 'target_domain': "www.google.com",
            'target_rr': "NS ns.ourattack.com",
            'policy': "auto", 'scan': "auto",
            'policy_time': 60, "run_time": 600, 'run_flag': "now"})
@bp.output({
    "code": Integer(),
    "msg": String()
})
# TODO：TARGET处理
# TODO: 需要更新接口，created_by
def make_task(json_data):
    task = Task(
        task_id = str(uuid.uuid1()),
        task_name = json_data["name"],
        agent_id = json_data["agent"],
        # created_by = "Admin",
        target_ip = str(json_data["target"]),
        # policy = json_data["policy"],
        status = "working" if json_data["run_flag"] == "now" else "stop",
        policy_delay = json_data["policy_time"],
        task_delay =json_data["run_time"],
        target_scan = json_data["scan"],
        target_domain = json_data["target_domain"],
        target_rtype = "",
        target_rr = json_data["target_rr"],
    )
    if task.policy == "sjqp":
        if task.target_rr == "" or task.target_domain == "":
            return {"code": 400, "msg": "数据欺骗缺乏目标域名或注入参数"}
    
    if task.target_rr != "":
        task.target_rtype, task.target_rr = task.target_rr.split(" ")

    # 查找所有在线的用于状态感知的agent
    agents = db.session.query(Agent).filter(and_(Agent.status==True, Agent.agent_type=='ztgz')).all()
    agents = random.sample(agents, min(10, len(agents)))
    selected_nodes_info = {}
    for agent in agents:
        selected_nodes_info[agent.agent_id] = agent.ipaddr.split("|")[0]
    task.SCAN_AGENT_ID_LIST = json.dumps(selected_nodes_info)
    
    # 插入task
    try:
        db.session.add(task)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        error(str(e))
        return {"code": 500, "msg": str(e)}
    
    # 任务策略初始化
    tp_id, p_exe, p_param = init_task_policy(json_data["policy"], task.target_ip, task.task_id)

    # 根据状态判断是否立刻执行
    if task.status == "working":
        err = deliver_task(task.agent_id, p_exe, p_param)
        if err is not None:
            error(str(err))
            return {"code": 500, "msg": str(err)}
    return {"code": 200, "msg": "ok"}


opsmap = {"start": "开始", "stop": "暂停", "cancel": "停止"}
statemap = {"working": "执行中", "stop": "暂停", "finish": "结束"}
# 合法逻辑映射，例如不能让一个暂停的任务开始，或是让一个正在运行的任务停止
ops_state = {"start": ["stop"], "stop": ["working"], "cancel": ["working", "stop"]}
# 操作与状态结果的映射关系
ops_state_result = {"start": "working", "stop": "stop", "cancel": "finish"}


# 操作任务开始停止控制接口
@bp.post("/ops")
@bp.doc("任务操作接口")
@bp.input({
    "taskid": String(required=True),
    "ops": String(required=True, validate=OneOf(["start", "stop", "cancel"]))
})
@bp.output({
    "code": Integer(),
    "msg": String(),
})
def ops_task(json_data):
    ops = json_data["ops"]
    # 操作中文名
    ops_cn = opsmap[json_data["ops"]]
    id = json_data["taskid"]

    task = db.session.query(Task).get(id)
    if task is None:
        return {"code": 400, "msg": "任务" + id + "不存在！！"}
    # 判断操作是否是逻辑上可执行的
    if task.status in ops_state[ops]:
        err = deliver_task(task.agent_id, "ops", ops)
        if err is not None:
            return {"code": 500, "msg": str(err)}
        task.status = ops_state_result[ops]
        db.session.commit()
        return {"code": 200, "msg": "任务" + task.task_id + "已" + ops_cn}
    else:
        return {"code": 400, "msg": "无法对一个" + statemap[task.status] + "的任务执行" + ops_cn + "操作"}


# 查询任务列表接口
@bp.get("/")
@bp.doc("任务列表信息获取接口")
@bp.input({
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10)
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(TaskSchema())),
    "total": Integer()
})
# TODO：DoH适配
def tasks_state(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]

    query = db.session.query(Task).filter().offset((page - 1) * per_page).limit(per_page)
    tasks = query.all()
    task_count = query.count()
    
    task_list = []
    for task in tasks:
        task_r = {}
        task_r["id"] = task.task_id
        task_r["target"] = task.target_ip
        task_r["name"] = task.task_name
        task_r["agent"] = task.agent_id
        task_r["target_domain"] = task.target_domain,
        task_r["target_rr"] = task.target_rr
        task_r["policy"] = task.policy
        task_r["create_time"] = task.created_time
        task_r["status"] = task.status
        task_list.append(task_r)
    return {"code": 200, "data": task_list, "total": task_count}


# 任务详情接口
@bp.get("/detail")
@bp.doc("任务执行状态时间轴信息获取接口")
@bp.input({
    "taskid": String(required=True),
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(TaskState()))
})
def task_info(query_data):
    task = db.session.query(Task).get(query_data["taskid"])
    if task is None:
        return {"code": 404, "data": []}
    task_policies = task.task_policies
    task_state_list = []
    if len(task_policies) == 0:
        return {"code": 404, "data": []}
    else:
        for task_policy in task_policies:
            task_state_list.append({
                "start_time": task_policy.tp_time,
                "policy_name": task_policy.policy_ref.p_name,
                "policy_param": task_policy.policy_param,
                "policy_id": task_policy.tp_id,
                "policy_status": "无效；原因为：超时未成功"
            })
        task_state_list[-1]["policy_status"] = "评估中"
    return {"code": 200, "data": task_state_list}


@bp.get("/tp")
@bp.doc("任务策略执行日志获取接口")
@bp.input({
    "id": Integer(required=True),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(TaskLogSchema())),
    "total": Integer()
})
def taskpolicy_log(query_data):
    id = query_data["id"]
    per_page = query_data["per_page"]
    page = query_data["page"]
    task_policy = db.session.get(TaskPolicy, id)
    if task_policy is None:
        return {"code": 404}

    logs = task_policy.task_logs
    # 分页
    total = len(logs)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_logs = logs[start:end]

    log_data = [{
        "time": log.created_time,
        "targetip": log.task_policy.task.target_ip,
        "ip": log.task_policy.task.agent.ipaddr,
        "level": log.tlog_level,
        "info": log.tlog_info
    } for log in paginated_logs]

    return {"code": 200,
            "data": log_data,
            "total": total}


@bp.doc("任务删除接口", "输入参数说明：</br>"
        + "id: 任务编号")
@bp.post("/del")
@bp.input({
    "id": String(required=True)
})
@bp.output({
    "code": Integer(),
    "msg": String()
})
def del_task(json_data):
    try:
        # 查找并删除任务
        task = db.session.query(Task).get(json_data["id"])
        if task:
            db.session.delete(task)
            db.session.commit()
            return {"code": "200", "msg": "任务删除成功"}
        else:
            return {"code": "404", "msg": "该任务id未找到！"}
    except SQLAlchemyError as e:
        db.session.rollback()
        error(str(e))
        return {"code": 500, "msg": str(e)}