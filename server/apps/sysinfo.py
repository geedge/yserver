# 系统信息接口

from apiflask import APIBlueprint, Schema
from apiflask.fields import Date, Integer, Nested, Dict, DateTime, String, List
from apiflask.validators import OneOf

# 测试用
from settings import *
from model import Syslog, User, Target, Agent
from exts import db

from datetime import timedelta

bp = APIBlueprint("仪表盘接口", __name__, url_prefix="/sys")

log_map = {
    "LOG_LEVEL": "level",
    "LOG_INFO": "info",
    "LOG_TIME": "time",
    "S_IP": "ip",
}


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
    "code": Integer(),
    "agent_num": Integer(),
    "task_num": Integer(),
    "workday": Integer(),
    "target": Nested(TargetOut())
})
def systate():
    from model import Task
    # 已部署代理节点数量
    agent_num = db.session.query(Agent).count()
    # 已执行任务数量（包括执行完毕和正在执行）
    task_num = db.session.query(Task).count()
    # 系统已运行天数
    workday = (datetime.date.today() - START_DAY).days
    # 已探测目标统计
    v6dns_num = db.session.query(Target).filter(Target.ipv6 == True).count()
    dnssec_num = db.session.query(Target).filter(Target.dnssec == True).count()
    doh_num = db.session.query(Target).filter(Target.doh == True).count()
    dot_num = db.session.query(Target).filter(Target.dot == True).count()

    # 返回结果
    return {
        "code": 200,
        "agent_num": agent_num,
        "task_num": task_num,
        "workday": workday,
        "target": {
            "v6dns": v6dns_num,
            "dnssec": dnssec_num,
            "doh": doh_num,
            "dot": dot_num
        }}


# 查询一周内每天不同探测目标的数量
@bp.get("/num/date")
@bp.doc("仪表盘柱状图数据获取接口", "查询一周内每天不同探测目标的数量")
@bp.output({
    "code": Integer(),
    "date_data": Dict(Date(), Nested(TargetOut()))
})
def target_date():
    # 计算今天和过去七天的日期范围
    today = datetime.date.today()
    seven_days_ago = today - timedelta(days=6)  # 计算包括今天在内的过去七天
    
    # 查询过去七天每天的数据
    date_data = {}
    for i in range(7):
        current_date = seven_days_ago + timedelta(days=i)
        next_day = current_date + timedelta(days=1)
        
        data = db.session.query(Target).filter(
                Target.updated_time >= current_date, 
                Target.updated_time < next_day)
        
        date_data[current_date] = {
            "v6dns": data.filter(Target.ipv6 == True).count(),
            "dnssec": data.filter(Target.dnssec == True).count(),
            "doh": data.filter(Target.doh == True).count(),
            "dot": data.filter(Target.dot == True).count()
        }
    
    return {"code": 200, "date_data": date_data}


# 系统操作日志获取接口
@bp.get("/log")
@bp.input({
    # 开始时间
    "begin": Date(),
    # 结束时间
    "end": Date(),
    # 日志等级
    "level": String(validate=OneOf(["INFO", "WARNING", "ERROR"])),
    # 用户名
    "user": String(),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location="query")
@bp.doc("系统操作日志获取接口", "返回系统的操作日志")
@bp.output({
    "code": Integer(),
    "log_data": List(Nested(LogOut())),
    "total": Integer()
})
def sys_log(query_data):
    begin = query_data.get('begin')
    end = query_data.get('end')
    level = query_data.get('level')
    user = query_data.get('user')
    per_page = query_data.get('per_page')
    page = query_data.get('page')
    query = db.session.query(Syslog, User).join(User, Syslog.user_id == User.user_id)
    if begin:
        query = query.filter(db.func.date(Syslog.log_time) >= begin)
    if end:
        query = query.filter(db.func.date(Syslog.log_time) <= end)
    if level:
        query = query.filter(Syslog.log_level == level)
    if user:
        query = query.filter(User.user_name == user)
    # 分页
    pagination = query.paginate(page=page, per_page=per_page)

    log_data = [{
        "time": log.Syslog.log_time,
        "level": log.Syslog.log_level,
        "info": log.Syslog.log_info,
        "user": log.User.user_name,
        "ip": log.Syslog.s_ip
    } for log in pagination.items]

    return {"code":200,
            "log_data": log_data,
            "total": pagination.total}
