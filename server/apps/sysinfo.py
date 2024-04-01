# 系统信息接口
import datetime

# 测试用
from faker import Faker
from faker.providers import date_time

fake = Faker('zh_CN')
fake.add_provider(date_time)

from apiflask import APIBlueprint, Schema
from apiflask.fields import Date, Integer, Nested, Dict, DateTime, String, List
from apiflask.validators import OneOf

bp = APIBlueprint("sys", __name__, url_prefix="/sys")


class TargetOut(Schema):
    v6dns = Integer()
    dnssec = Integer()
    doh = Integer()
    dot = Integer()


class LogOut(Schema):
    time = DateTime()
    level = String(validate=OneOf(["INFO", "WARNING", "ERROR"]))
    info = String()
    user = String()
    ip = String()


# 统计数量获取接口
@bp.get("/num")
@bp.doc("系统信息获取接口", "返回当前系统状态,包括已部署代理节点数量、已执行任务次数、系统已运行天数以及已探测目标统计")
@bp.output({
    "agent_num": Integer(),
    "task_num": Integer(),
    "workday": Integer(),
    "target": Nested(TargetOut())
})
def systate():
    # TODO:从数据库读取信息并统计
    # 已部署代理节点数量
    agent_num = fake.random.randint(10, 100)
    # 已执行任务数量（包括执行完毕和正在执行）
    task_num = fake.random.randint(10, 100)
    # 系统已运行天数
    workday = fake.random.randint(10, 100)
    # 已探测目标统计
    v6dns_num = fake.random.randint(10, 100)
    dnssec_num = fake.random.randint(10, 100)
    doh_num = fake.random.randint(10, 100)
    dot_num = fake.random.randint(10, 100)
    # 返回结果
    return {
        "agent_num": agent_num,
        "task_num": task_num,
        "workday": workday,
        "target": {
            "v6dns": v6dns_num,
            "dnssec": dnssec_num,
            "doh": doh_num,
            "dot": dot_num
        }}


# 随时间的不同协议服务数量变化接口
@bp.get("/num/date")
@bp.doc("仪表盘柱状图数据获取接口", "返回当前不同探测目标在一周内的数量变化情况")
@bp.output({
    "date_data": Dict(Date(), Nested(TargetOut()))
})
def target_date():
    today = datetime.date.today()
    dates = {}
    day = 1
    while day < 8:
        d = today - datetime.timedelta(day)
        # TODO:从数据库读取并统计
        dates[d] = {
            "v6dns": fake.random.randint(10, 20) * day,
            "dnssec": fake.random.randint(10, 20) * day,
            "doh": fake.random.randint(10, 20) * day,
            "dot": fake.random.randint(10, 20) * day
        }
        day += 1
    return {"date_data": dates}


@bp.get("/log")
@bp.doc("系统操作日志获取接口", "返回系统的操作日志")
@bp.output({
    "log_data": List(Nested(LogOut()))
})
def sys_log():
    log_list = []
    # TODO:具体实现
    for i in range(30):
        log_list.append({
            "time": fake.date_time_between(start_date="-1y"),
            "level": fake.word(ext_word_list=["INFO", "WARNING", "ERROR"]),
            "info": fake.text(max_nb_chars=20, ext_word_list=None),
            "user": fake.name(),
            "ip": fake.ipv4()
        })
    return {"log_data": log_list}
