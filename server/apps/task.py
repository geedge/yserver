# 任务管理接口
from datetime import datetime, timedelta
import json
import time
import uuid

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf
from flask import current_app
from sqlalchemy import and_, desc, select
from sqlalchemy.exc import SQLAlchemyError

from .target import start_task_monitoring, target_GZ, task_monitoring, stop_task_monitoring
from model import Target, Task, Agent, TargetStatus
from .agentcomm import deliver_task, stop_task_deliver
from .policy import *
from .util import error, is_ipaddress, debug

from exts import db, scheduler
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
    status = String(validate=OneOf(["working", "stopped", "finished"]))


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
    evaluate_status = String()
    # 当前状态
    policy_status = String()
    # 策略类型
    policy_type = String()
    


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
    "target": IP(required=False),
    # 执行代理
    "agent": String(),
    # 目标域名
    "target_domain": String(required=False),
    # 期望注入记录
    "target_rr": String(required=False),
    # 期望策略
    "policy": String(validate=OneOf(["auto", "ddos", "sjqp"]), load_default="auto"),
    # 状态感知方式
    "scan": String(validate=OneOf(["auto", "icmp", "dns", "tcp", "record"]), load_default="auto"),
    # 策略切换时限,单位分钟
    "policy_time": Integer(load_default=60),
    # 任务执行时限，单位分钟
    "run_time": Integer(load_default=600),
    # 运行配置
    "run_flag": String(validate=OneOf(["now", "man"]), load_default="now")
}, example={'name': "test_task", 'target': "47.76.239.205", 'agent': "inrz674e", 'target_domain': "www.google.com",
            'target_rr': "NS ns.ourattack.com",
            'policy': "auto", 'scan': "auto",
            'policy_time': 60, "run_time": 600, 'run_flag': "now"})
@bp.output({
    "code": Integer(),
    "msg": String()
})
# TODO: 需要更新接口，created_by
def make_task(json_data):
    task = Task(
        task_id=str(uuid.uuid1()),
        task_name=json_data.get("name"),
        agent_id=json_data.get("agent"),
        # created_by = "Admin",
        # target_ip=str(json_data.get("target")),
        ptype = json_data["policy"],
        status="working" if json_data.get("run_flag") == "now" else "stop",
        policy_delay=json_data.get("policy_time"),
        task_delay=json_data.get("run_time"),
        target_scan=json_data.get("scan"),
        target_domain=json_data.get("target_domain"),
        # target_rtype=,
        target_rr=json_data.get("target_rr")
    )
    if task.ptype == "sjqp":
        if task.target_rr == "" or task.target_domain == "":
            return {"code": 400, "msg": "数据欺骗缺乏目标域名或注入参数"}

    if task.target_rr is not None:
        task.target_rtype, task.target_rr = task.target_rr.split(" ")

    # 关联目标
    Ip = str(json_data.get("target"))
    ip_version = is_ipaddress(Ip)
    target = None
    if ip_version == 4 :
        target = db.session.query(Target).filter(Target.addrv4==Ip).first()
    elif ip_version == 6:
        target = db.session.query(Target).filter(Target.addrv6==Ip).first()
    
    
    # 不存在该目标的相关记录，自动探测并存入数据库
    if not target:
        target = target_GZ(Ip)
    task.target = target

    # 查找所有在线的用于状态感知的agent
    agents = db.session.query(Agent).filter(and_(Agent.status == True, Agent.agent_type == 'ztgz')).all()
    agents = random.sample(agents, min(10, len(agents)))
    selected_nodes_info = {}
    for agent in agents:
        selected_nodes_info[agent.agent_id] = agent.ipaddr.split("|")[0] + ":" + str(agent.port)
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
    # task_policy = init_task_policy(task)
    task_policy = get_policy_dic(task)
    # 创建锚点
    task_monitoring(task)
    
    # 初始化决策中心
    # db.session.close()
    # task_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()
    # status = db.session.query(TargetStatus).filter_by(tp_id=task_policy.tp_id).order_by(TargetStatus.time.desc()).first()

    # req = {
    #     "clxz": task_policy.Policy.p_type,
    #     "script": task_policy.Policy.p_name,
    #     "mbgz": task.target.protect,
    #     "ztgz": {
    #         "icmp": status.icmp,
    #         "tcp": status.tcp,
    #         "dns": status.dns,
    #         "record": status.recorde,
    #     },
    #     "para": task_policy.policy_param,
    #     "task_id": task.task_id
    # }
    # url = f"http://localhost:12535/initial"
    # response = requests.post(url, json=req)

    # 开启监控
    start_task_monitoring(task)
    start_policy_change_timer(task)

    # 根据状态判断是否立刻执行
    if task.status == "working":
        err = deliver_task(task_policy)
        if err is not None:
            error(str(err))
            return {"code": 500, "msg": str(err)}
    return {"code": 200, "msg": "ok"}


def policy_change_timer(task):
    with scheduler.app.app_context():
        task_policy=db.session.query(TaskPolicy).get(task.task_policies[-1].tp_id)
        if not effective_detection(task_policy=task_policy):
            adjust_task(task=task)

# 任务切换倒计时
# 从任务下发开始计算，倒计时三百秒切换任务
def start_policy_change_timer(task):
    with scheduler.app.app_context():
        scheduler.add_job(
            func=policy_change_timer,  # 要执行的函数
            trigger='interval',  # 触发器类型为间隔
            args = (task, ),  # 传递给函数的参数
            id = f"{task.task_id}chnage",
            seconds = 600
        )
        scheduler.add_job(
            func = fail_task, 
            trigger = 'date', 
            args = (task, ),
            id = f"{task.task_id}fail",
            run_date = datetime.now() + timedelta(seconds=int(task.task_delay))
        )

def stop_policy_change_timer(task):
    scheduler.remove_job(f"{task.task_id}chnage")

# 任务成功检测
def effective_detection(task_policy):
    with scheduler.app.app_context():
        base_policy = db.session.query(TaskPolicy).filter(TaskPolicy.for_task==task_policy.for_task).order_by(TaskPolicy.tp_time.asc()).first()
        base = db.session.query(TargetStatus).filter_by(tp_id=base_policy.tp_id).order_by(TargetStatus.time.asc()).first()
        now = db.session.query(TargetStatus).filter_by(tp_id=task_policy.tp_id).order_by(TargetStatus.time.desc()).first()

        rec = None
        p_type = db.session.query(Policy).filter_by(p_id=task_policy.policy).first().p_type
        if p_type=="ddos":
            target_scan = db.session.query(Task).filter_by(task_id = task_policy.for_task).first().target_scan
            if target_scan=="auto" or target_scan=="icmp":
                rec = base.icmp*5 < now.icmp       
            elif target_scan=="tcp":
                rec = base.tcp*5 < now.tcp       
            elif target_scan=="dns":
                rec = base.dns*5 < now.dns       
        elif p_type=="sjqp":
            rec = base.recorde!=now.recorde
            pass
        debug(f"能行吗{rec}：是{p_type}")
        return rec

def adjust_task(task):
    with scheduler.app.app_context():
        debug("再试试")
        task_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()
        stop_task_deliver(task_policy)
        # center_process_unit(task)
        get_policy_dic(task)
        task_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()
        task.status = "working"
        db.session.commit()
        deliver_task(task_policy)


def stop_task(task):
    with scheduler.app.app_context():
        debug("暂停啦啦")
        task_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()
        task.status = "stopped"
        stop_task_monitoring(task)
        stop_policy_change_timer(task)
        stop_task_deliver(task_policy)
        db.session.commit()

def finish_task(task):
    with scheduler.app.app_context():
        task = db.session.query(Task).filter_by(task_id = task.task_id).first()
        debug("成功啦")
        task_policy = task.task_policies[-1]
        task.status = "finish"
        stop_task_monitoring(task)
        stop_policy_change_timer(task)
        stop_task_deliver(task_policy)
        db.session.commit()

def fail_task(task):
    with scheduler.app.app_context():
        task = db.session.query(Task).filter_by(task_id = task.task_id).first()
        debug("失败")
        task_policy = task.task_policies[-1]
        task.status = "fail"
        stop_task_monitoring(task)
        stop_policy_change_timer(task)
        stop_task_deliver(task_policy)
        db.session.commit()

operation_map = {"start": "开始", "stop": "暂停"}
status_map = {"working": "执行中", "stopped": "暂停"}
# 合法的状态转移逻辑，例如，暂停的任务不能开始，正在执行的任务不能停止
valid_transitions = {"start": ["stopped"], "stop": ["working"]}
# 操作与状态变更结果的映射关系
operation_result_map = {"start": "working", "stop": "stopped"}

# 操作任务开始和停止控制接口
@bp.post("/ops")
@bp.doc("任务操作接口")
@bp.input({
    "taskid": String(required=True),
    "ops": String(required=True, validate=OneOf(["start", "stop"]))
})
@bp.output({
    "code": Integer(),
    "msg": String(),
})
def handle_task_operation(json_data):
    operation = json_data["ops"]
    task_id = json_data["taskid"]

    task = db.session.query(Task).get(task_id)
    if not task:
        return {"code": 400, "msg": f"任务 {task_id} 不存在！"}
    

    if task.status not in valid_transitions.get(operation, []):
        return {"code": 400, "msg": f"无法对一个 {status_map[task.status]} 的任务执行 {operation_map[operation]} 操作"}
    
    if operation == "start":
        deliver_task(copy_task_policy(task))
    else:  # operation is "stop"
        latest_task_policy = db.session.query(TaskPolicy)\
            .filter_by(for_task=task.task_id)\
            .order_by(TaskPolicy.tp_time.desc())\
            .first()
        stop_task(latest_task_policy)

    task.status = operation_result_map[operation]
    db.session.commit()
    
    return {"code": 200, "msg": f"任务 {task.task_id} 已 {operation_map[operation]}"}




# 查询任务列表接口
@bp.get("/")
@bp.doc("任务列表信息获取接口")
@bp.input({
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10),
    "task_id":String(required=False)
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
    task_id = query_data.get("task_id")
    if task_id:
        query = db.session.query(Task).filter_by(task_id = task_id)
    else:
        query = db.session.query(Task).filter().order_by(Task.created_time.desc())
    task_count = query.count()
    tasks = query.offset((page - 1) * per_page).limit(per_page).all()

    task_list = []
    for task in tasks:
        task_r = {}
        task_r["id"] = task.task_id
        task_r["target"] = f"{task.target.addrv4}|{task.target.addrv6}"
        task_r["name"] = task.task_name
        task_r["agent"] = task.agent_id
        task_r["target_domain"] = task.target_domain
        task_r["target_rr"] = task.target_rr
        task_r["policy"] = task.ptype
        task_r["create_time"] = task.created_time
        task_r["status"] = task.status
        task_list.append(task_r)
    return {"code": 200, "data": task_list, "total": task_count}


def calculate_response_rate(task_policy):
    
    base_policy = db.session.query(TaskPolicy).filter(TaskPolicy.for_task==task_policy.for_task).order_by(TaskPolicy.tp_time.asc()).first()
    base = db.session.query(TargetStatus).filter_by(tp_id=base_policy.tp_id).order_by(TargetStatus.time.desc()).first()

    # 查询总记录数和大于 threshold 的记录数
    total_count = db.session.query(TargetStatus).filter_by(tp_id=task_policy.tp_id).count()
    
    # icmp
    count_above_threshold = db.session.query(TargetStatus).filter(
        TargetStatus.tp_id == task_policy.tp_id,
        TargetStatus.icmp > 1.5*base.icmp
    ).count()
    icmp_ratio = (count_above_threshold / total_count) if total_count > 0 else 0

    count_above_threshold = db.session.query(TargetStatus).filter(
        TargetStatus.tp_id == task_policy.tp_id,
        TargetStatus.tcp > 1.5*base.tcp
    ).count()
    tcp_ratio = (count_above_threshold / total_count) if total_count > 0 else 0

    count_above_threshold = db.session.query(TargetStatus).filter(
        TargetStatus.tp_id == task_policy.tp_id,
        TargetStatus.dns > 1.5*base.dns
    ).count()
    dns_ratio = (count_above_threshold / total_count) if total_count > 0 else 0

    res = {
        "icmp_response_rate": 1-icmp_ratio,
        "tcp_response_rate": 1-tcp_ratio,
        "dns_response_rate": 1-dns_ratio,
    }
    return res


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
    # task_policies = task.task_policies
    task_policies = db.session.query(TaskPolicy).filter(TaskPolicy.for_task== task.task_id).order_by(TaskPolicy.tp_time.asc()).all()
    task_state_list = []
    if len(task_policies) == 0:
        return {"code": 404, "data": []}
    else:
        # 初始化 task_state_list
        task_state_list = []

        # 遍历 task_policies，构建任务状态列表
        for task_policy in task_policies:
            # 查询与当前 task_policy 相关的 TargetStatus，按时间降序排序，取最新一条
            delay = db.session.query(TargetStatus).filter_by(tp_id=task_policy.tp_id).order_by(TargetStatus.time.desc()).first()
            # 构建任务状态字典
            task_state = {
                "start_time": task_policy.tp_time,
                "policy_name": task_policy.Policy.p_name,
                "policy_param": task_policy.policy_param,
                "policy_id": task_policy.tp_id,
                "policy_status": "stopped",
                "evaluate_status": str(json.dumps({
                    "icmp": delay.icmp,
                    "tcp": delay.tcp,
                    "dns": delay.dns,
                    "record": delay.recorde,
                    "service_response_rate": calculate_response_rate(task_policy),
                    "tampering_success_rate": effective_detection(task_policy),
                })) if delay else "评估进行中",
                "policy_type": task_policy.Policy.p_type
            }

            task_state_list.append(task_state)

        # 处理最后一个任务状态
        last_task_state = task_state_list[-1]
        # last_task_policy = task_policies[-1]

        # 根据 task 的状态更新任务状态
        last_task_state["policy_status"] = task.status


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
        "targetip": f"{log.task_policy.task.target.addrv4}|{log.task_policy.task.target.addrv4}",
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
