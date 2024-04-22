# 任务管理接口
import datetime
import random

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf

from .util import fake, da

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
    # 策略切换时限
    "policy_time": Integer(),
    # 任务执行时限
    "run_time": Integer(),
    # 运行配置
    "run_flag": String(validate=OneOf(["now", "man"]))
})
@bp.output({
    "code": Integer(),
    "msg": String()
})
# TODO：创建任务接口具体实现
def make_task(json_data):
    print(json_data)
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
# TODO：任务详情接口具体实现
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
    "id": String(required=True),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location="query")
@bp.output({
    "code": Integer(),
    "data": List(Nested(TaskLog())),
    "total": Integer()
})
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
