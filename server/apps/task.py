# 任务管理接口
import datetime
import random

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, IP, DateTime, List, Nested
from apiflask.validators import OneOf

from .util import fake

bp = APIBlueprint("任务管理接口集合", __name__, url_prefix="/task")


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
    # 执行输出
    policy_output = List(Nested(TaskLog()))
    # 效果评估
    policy_status = String()


# 创建任务接口
@bp.post("/create")
@bp.doc("任务创建接口", "字段含义详见task.py文件注释")
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
    "scan": String(validate=OneOf(["auto", "delay", "record"])),
    # 策略切换时限
    "policy_time": Integer(),
    # 任务执行时限
    "run_time": Integer(),
    # 运行配置
    "run_flag": String(validate=OneOf(["now", "man"]))
})
# TODO：创建任务接口具体实现
def make_task(json_data):
    print(json_data)
    return {"msg": "ok"}


opsmap = {"start": "开始", "stop": "暂停", "cancel": "停止"}


# 操作任务开始停止控制接口
@bp.post("/ops")
@bp.doc("任务操作接口")
@bp.input({
    "taskid": String(required=True),
    "ops": String(required=True, validate=OneOf(["start", "stop", "cancel"]))
})
# TODO：操作任务开始停止控制接口具体实现
def ops_task(json_data):
    ops = opsmap[json_data["ops"]]
    return {"msg": "任务" + json_data["taskid"] + "已" + ops}


# 查询任务列表接口
@bp.get("/")
@bp.doc("任务列表信息获取接口")
@bp.input({
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10)
}, location="query")
@bp.output({
    "data": List(Nested(Task()))
})
# TODO：查询任务状态接口具体实现
def tasks_state(query_data):
    task_list = []
    for _ in range(query_data["per_page"]):
        task_list.append({
            "id": fake.random.randint(1, 10000),
            "target": fake.ipv4(),
            "name": "示例任务",
            "agent": fake.random.randint(1, 10000),
            "target_domain": fake.domain_name(),
            "target_rr": "NS attack.com",
            "policy": random.choice(["auto", "ddos", "sjqp"]),
            "create_time": fake.date_time_between(start_date="-1y"),
            "status": random.choice(["working", "stop", "finish"])
        })
    return {"data": task_list}


# 任务详情接口
@bp.get("/detail")
@bp.doc("任务执行状态时间轴信息获取接口")
@bp.input({
    "taskid": String(required=True),
}, location="query")
@bp.output({
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
            "policy_output": [{
                "time": fake.date_time_between(start_date="-1y"),
                "ip": "192.168.1.1",
                "targetip": "2406:1234:1234:1234:1234:1234:1234:1234",
                "level": random.choice(["INFO", "WARNING", "ERROR"]),
                "info": fake.text(max_nb_chars=20, ext_word_list=None)
            } for _ in range(20)],
            "policy_status": "无效；原因为：超时未成功"
        })
    # 当前正在执行的策略
    task_state_list.append({
        "start_time": datetime.datetime.now(),
        "policy_name": random.choice(["IPv6", "DNSSEC", "DoT", "DoH"]) + "  " + random.choice(["DDoS", "数据欺骗"]),
        "policy_param": random.choice(["攻击速率: 1000pps", "目标域名: www.google.com | 目标记录: NS attack.com"]),
        "policy_output": [{
            "time": fake.date_time_between(start_date="-1y"),
            "ip": "192.168.1.1",
            "targetip": "2406:1234:1234:1234:1234:1234:1234:1234",
            "level": random.choice(["INFO", "WARNING", "ERROR"]),
            "info": fake.text(max_nb_chars=20, ext_word_list=None)
        } for _ in range(20)],
        "policy_status": "评估中"
    })
    return {"data": task_state_list}
