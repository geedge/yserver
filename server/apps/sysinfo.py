# 系统信息接口

from apiflask import APIBlueprint, Schema
from apiflask.fields import Date, Integer, Nested, Dict, DateTime, String, List
from apiflask.validators import OneOf

# 测试用
from settings import *
from .util import da

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
    "agent_num": Integer(),
    "task_num": Integer(),
    "workday": Integer(),
    "target": Nested(TargetOut())
})
def systate():
    # 已部署代理节点数量
    agent_num = da.count_data("agent")
    # 已执行任务数量（包括执行完毕和正在执行）
    task_num = da.count_data("task")
    # 系统已运行天数
    workday = datetime.date.today() - START_DAY
    # 已探测目标统计
    v6dns_num = da.count_data("target", {"IPv6": True})
    dnssec_num = da.count_data("target", {"DNSSEC": True})
    doh_num = da.count_data("target", {"DOH": True})
    dot_num = da.count_data("target", {"DOT": True})
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
        dates[d] = {
            "v6dns": da.count_data_by_time("target", time=d, search={"IPv6": True}),
            "dnssec": da.count_data_by_time("target", time=d, search={"DNSSEC": True}),
            "doh": da.count_data_by_time("target", time=d, search={"DOH": True}),
            "dot": da.count_data_by_time("target", time=d, search={"DOT": True})
        }
        day += 1
    return {"date_data": dates}


# 系统操作日志获取接口
@bp.get("/log")
@bp.input({
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location="query")
@bp.doc("系统操作日志获取接口", "返回系统的操作日志")
@bp.output({
    "log_data": List(Nested(LogOut()))
})
def sys_log(query_data):
    # 每页显示多少项
    per_page = query_data["per_page"]
    # 页数
    page = query_data["page"]
    tabs = {
        "syslog": MYSQL_TAB_SYSLOG,
        "user": MYSQL_TAB_USER,
        "start": (page - 1) * per_page,
        "stop": per_page
    }
    sql = """SELECT 
        s.LOG_LEVEL as level,
        s.LOG_INFO as info, 
        s.LOG_TIME as time,
        s.S_IP as ip,
        CONCAT(u.USER_NAME,"(ID:",u.USER_ID,")") as user
    from %(syslog)s s,%(user)s u WHERE s.USER_ID=u.USER_ID LIMIT %(start)s,%(stop)s  """ % tabs
    da.cursor.execute(sql)
    log_list = da.cursor.fetchall()
    return {"log_data": log_list}
