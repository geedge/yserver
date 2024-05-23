# 任务管理接口
import json
import uuid

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf

from .agentcomm import deliver_task
from .policy import *
from .util import fake, da, error, debug

bp = APIBlueprint("任务管理接口集合", __name__, url_prefix="/task")

# 数据库列与返回值的键对应关系
task_response_map = {
    "TASK_ID": "id",
    "TARGET_IP": "target",
    "TASK_NAME": "name",
    "AGENT_ID": "agent",
    "TARGET_DOMAIN": "target_domain",
    "TARGET_RR": "target_rr",
    "POLICY": "policy",
    "CREATE_TIME": "create_time",
    "STATUS": "status",
}


class Task(Schema):
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
class TaskLog(Schema):
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
def make_task(json_data):
    # 请求参数转储到变量
    name = json_data["name"]
    target = str(json_data["target"])
    agent_id = json_data["agent"]
    tdomain = json_data["target_domain"]
    target_rr = json_data["target_rr"]
    policy_type = json_data["policy"]
    scan = json_data["scan"]
    policy_time = json_data["policy_time"]
    run_flag = json_data["run_flag"]
    run_time = json_data["run_time"]

    # 任务编号生成
    t_id = str(uuid.uuid1())

    # 任务信息生成

    task_info = {
        "t_id": t_id,
        "name": name,
        "target": target,
        "ag_id": agent_id,
        "p_delay": policy_time,
        "t_delay": run_time,
        "scan": scan,
        "status": "working" if run_flag == "now" else "stop",
        "policy": policy_type,
        "tdomain": tdomain,
        "target_rr": target_rr,
        "target_rtype": ""
    }

    # 输入参数检查处理
    warn = valid_task_info(task_info)
    if warn is not None:
        return {"code": 400, "msg": warn}
    if task_info["target_rr"] != "":
        rr = task_info["target_rr"].split(" ")
        task_info["target_rtype"], task_info["target_rr"] = rr[0], rr[1]

    # 添加表名
    task_info["tab"] = MYSQL_TAB_TASK
    # 若目标为IP地址
    if is_ipaddress(target) is not None:
        task_info["TARGET"] = "TARGET_IP"
    # 若目标为域名，视为DoH服务
    else:
        task_info["TARGET"] = "TARGET_DOH"

    # 添加状态探测节点，用于状态感知
    scan_node_sql = """
    SELECT AGENT_ID,IPADDR
    FROM %s
    WHERE STATUS='1' AND AGENT_TYPE='ztgz'
    LIMIT 50;
    """ % MYSQL_TAB_AGENT
    da.cursor.execute(scan_node_sql)
    # 所有在线的支持状态感知的代理
    all_nodes = da.cursor.fetchall()
    # 随机选择10个
    selected_nodes = random.choices(all_nodes, k=10 if len(all_nodes) > 10 else len(all_nodes))
    # 将选择的代理节点ID和对应IPv4地址存储为字典，键为代理ID，值为代理的IPv4地址
    selected_nodes_info = {'{}'.format(n['AGENT_ID']): '{}'.format(str(n['IPADDR']).split("|")[0]) for n in
                           selected_nodes}
    task_info["nodes"] = json.dumps(selected_nodes_info)

    # sql语句组合
    sql = """
    INSERT INTO %(tab)s (
    TASK_ID,
    TASK_NAME, 
    AGENT_ID,  
    STATUS, 
    POLICY_DELAY,
    TASK_DELAY,
    TARGET_SCAN,
    TARGET_DOMAIN,
    TARGET_RTYPE,
    TARGET_RR,
    %(TARGET)s,
    SCAN_AGENT_ID_LIST)
    VALUES (
    '%(t_id)s',
    '%(name)s',
    '%(ag_id)s',
    '%(status)s',
    '%(p_delay)s',
    '%(t_delay)s',
    '%(scan)s',
    '%(tdomain)s',
    '%(target_rtype)s',
    '%(target_rr)s',
    '%(target)s',
    '%(nodes)s'
    );
    """ % task_info
    debug(sql)
    da.cursor.execute(sql)
    da.conn.commit()

    # 任务策略初始化
    tp_id, p_exe, p_param = init_task_policy(policy_type, target, t_id)
    update_policy_sql = """
    UPDATE %s
    SET POLICY='%s'
    WHERE TASK_ID='%s';
    """ % (MYSQL_TAB_TASK, tp_id, t_id)
    da.cursor.execute(update_policy_sql)
    da.conn.commit()

    # 根据run_flag判断是否立刻执行
    if run_flag == "now":
        err = deliver_task(agent_id, p_exe, p_param)
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

    # 查询目标任务状态
    sql = """
    SELECT AGENT_ID,STATUS 
    FROM %s
    WHERE TASK_ID='%s';
    """ % (MYSQL_TAB_TASK, id)
    da.cursor.execute(sql)
    data = da.cursor.fetchall()
    if len(data) == 0:
        return {"code": 400, "msg": "任务" + id + "不存在！！"}
    # 判断操作是否是逻辑上可执行的
    if data[0]["STATUS"] in ops_state[ops]:
        # 向对应代理下发控制指令
        err = deliver_task(data[0]["AGENT_ID"], "ops", ops)
        if err is not None:
            return {"code": 500, "msg": str(err)}
        task_update_status_sql = """
        UPDATE %s
        SET STATUS='%s'
        WHERE TASK_ID='%s';""" % (MYSQL_TAB_TASK, ops_state_result[ops], id)
        da.cursor.execute(task_update_status_sql)
        da.conn.commit()
        return {"code": 200, "msg": "任务" + json_data["taskid"] + "已" + ops_cn}
    else:
        return {"code": 400, "msg": "无法对一个" + statemap[data[0]["STATUS"]] + "的任务执行" + ops_cn + "操作"}


# 查询任务列表接口
@bp.get("/")
@bp.doc("任务列表信息获取接口")
@bp.input({
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10)
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(Task())),
    "total": Integer()
})
# TODO：DoH适配
def tasks_state(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]

    # 任务列表
    task_list = []
    res = da.get_data(data_type="task",
                      offset=(page - 1) * per_page, limit=per_page)
    res_count = da.count_data(data_type="task")
    for r in res:
        task = {}
        for key, value in r.items():
            try:
                task[task_response_map[key]] = value
            except KeyError:
                continue
        task_list.append(task)
    return {"code": 200, "data": task_list, "total": res_count}


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
    taskid = query_data["taskid"]

    # 任务状态列表
    sql = """
    SELECT tp.TP_TIME as tp_time, p.P_NAME as p_name, tp.POLICY_PARAM as tp_param,tp.TP_ID as tp_id
    FROM %s as tp,%s as p
    WHERE tp.POLICY=p.P_ID AND tp.FOR_TASK='%s'
    ORDER BY TP_TIME;
    """ % (MYSQL_TAB_TASKPOLICY, MYSQL_TAB_POLICY, taskid)
    da.cursor.execute(sql)
    data = da.cursor.fetchall()
    task_state_list = []
    # 过往记录
    for d in data:
        task_state_list.append({
            "start_time": d["tp_time"],
            "policy_name": d["p_name"],
            "policy_param": d["tp_param"],
            "policy_id": d["tp_id"],
            "policy_status": "无效；原因为：超时未成功"
        })
    # 最后一项为当前正在执行的策略
    task_state_list[-1]["policy_status"] = "评估中"
    return {"code": 200, "data": task_state_list}


@bp.get("/tp")
@bp.doc("任务策略执行日志获取接口")
@bp.input({
    # 任务策略id (taskpolicy)
    "id": String(required=True),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(TaskLog())),
    "total": Integer()
})
# TODO：功能实现(For 石昊月师弟)
def taskpolicy_log(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]
    policy_output = [{
        "time": fake.date_time_between(start_date="-1y"),
        "ip": "192.168.1.1",
        "targetip": "2406:1234:1234:1234:1234:1234:1234:1234",
        "level": random.choice(["INFO", "WARNING", "ERROR"]),
        "info": fake.text(max_nb_chars=20, ext_word_list=None)
    } for _ in range(per_page)]

    return {"code": 200, "data": policy_output, "total": 10 * per_page}


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
    taskid = json_data["id"]
    sql = """
    DELETE 
    FROM %s 
    WHERE TASK_ID='%s';
    """ % (MYSQL_TAB_TASK, taskid)
    try:
        da.cursor.execute(sql)
        da.conn.commit()
        if da.cursor.rowcount == 0:
            return {"code": "404", "msg": "该任务id未找到！"}
    except Exception as e:
        error(str(e))
        return {"code": 500, "msg": str(e)}
    return {"code": 200, "msg": "ok"}
