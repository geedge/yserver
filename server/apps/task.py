# 任务管理接口
import uuid

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf

from settings import *
from .agentcomm import deliver_task
from .policy import *
from .util import fake, da, error, string_to_mysql

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
    id = Integer()
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
    "target_domain": String(load_default=""),
    # 期望注入记录
    "target_rr": String(load_default=""),
    # 期望策略
    "policy": String(validate=OneOf(["auto", "ddos", "sjqp"])),
    # 状态感知方式
    "scan": String(validate=OneOf(["auto", "icmp", "dns", "tcp", "record"])),
    # 策略切换时限
    "policy_time": Integer(load_default=60),
    # 任务执行时限
    "run_time": Integer(load_default=600),
    # 运行配置
    "run_flag": String(validate=OneOf(["now", "man"]))
}, example={'name': "test_task", 'target': "1.1.1.1", 'agent': "3e94bsn7", 'target_domain': "www.google.com",
            'target_rr': 'NS ns.attack.com',
            'policy': "auto", 'scan': "auto", "run_flag": "now", 'run_time': 60, 'policy_time': 60})
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
    # 若目标为IP地址
    if is_ipaddress(target) is not None:
        task_info["TARGET"] = "TARGET_IP"
    # 若目标为域名，视为DoH服务
    else:
        task_info["TARGET"] = "TARGET_DOH"

    # 输入参数检查处理
    warn = valid_task_info(task_info)
    if warn is not None:
        return {"code": 400, "msg": warn}
    if task_info["target_rr"] != "":
        task_info["target_rtype"], task_info["target_rr"] = tuple(task_info["target_rr"].split(" "))

    # 参数格式处理
    task_info = string_to_mysql(task_info)

    # 添加表名
    task_info["tab"] = MYSQL_TAB_TASK

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
    %(TARGET)s)
    VALUES (
    %(t_id)s,
    %(name)s,
    %(ag_id)s,
    %(status)s,
    %(p_delay)s,
    %(t_delay)s,
    %(scan)s,
    %(tdomain)s,
    %(target_rtype)s,
    %(target_rr)s,
    %(target)s
    );
    """ % task_info
    da.cursor.execute(sql)
    da.conn.commit()

    # 任务策略初始化
    tp_id, p_exe, p_param = init_task_policy(policy_type, target, t_id)
    update_policy_sql = """
    UPDATE %s
    SET POLICY=%s
    WHERE TASK_ID=%s;
    """ % (MYSQL_TAB_TASK, tp_id, "\'" + t_id + "\'")
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
# TODO：操作任务开始停止控制接口具体实现
def ops_task(json_data):
    ops = opsmap[json_data["ops"]]
    return {"code": 200, "msg": "任务" + json_data["taskid"] + "已" + ops}


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
# TODO：查询任务状态接口具体实现
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
            task[task_response_map[key]] = value
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
# TODO：任务详情信息获取接口具体实现
def task_info(query_data):
    print(query_data)
    round = random.randint(1, 10)
    task_state_list = []
    # 过往记录
    for _ in range(round):
        task_state_list.append({
            "start_time": fake.date_time_between(start_date="-1y"),
            "policy_name": random.choice(["IPv6", "DNSSEC", "DoT", "DoH"]) + "  " + random.choice(["DDoS", "数据欺骗"]),
            "policy_param": random.choice(["攻击速率: 1000pps", "目标域名: www.google.com | 目标记录: NS attack.com"]),
            "policy_id": str(fake.random.randint(1, 10000)),
            "policy_status": "无效；原因为：超时未成功"
        })
    # 当前正在执行的策略
    task_state_list.append({
        "start_time": datetime.datetime.now(),
        "policy_name": random.choice(["IPv6", "DNSSEC", "DoT", "DoH"]) + "  " + random.choice(["DDoS", "数据欺骗"]),
        "policy_param": random.choice(["攻击速率: 1000pps", "目标域名: www.google.com | 目标记录: NS attack.com"]),
        "policy_id": str(fake.random.randint(1, 10000)),
        "policy_status": "评估中"
    })
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
