# 系统信息接口
from apiflask import APIBlueprint

bp = APIBlueprint("sys", __name__, url_prefix="/sys")


# 统计数量获取接口
@bp.get("/num")
@bp.doc("系统信息获取接口", "返回当前系统状态,包括已部署代理节点数量、已执行任务次数、系统已运行天数以及已探测目标统计")
# TODO:从数据库读取并统计
def systate():
    # 已部署代理节点数量
    agent_num = 10
    # 已执行任务数量（包括执行完毕和正在执行）
    task_num = 100
    # 系统已运行天数
    workday = 10
    # 已探测目标统计
    v6dns_num = 100
    dnssec_num = 100
    doh_num = 111
    dot_num = 101
    # 返回结果
    return {"data": {
        "agent_num": agent_num,
        "task_num": task_num,
        "workday": workday,
        "target": {
            "v6dns": v6dns_num,
            "dnssec": dnssec_num,
            "doh": doh_num,
            "dot": dot_num
        }}}


# 随时间的不同协议服务数量变化接口
@bp.get("/num/date")
@bp.doc("目标数量变化信息获取接口", "返回当前不同探测目标在一周内的数量变化情况")
# TODO:从数据库读取并统计
def target_date():
    pass


@bp.get("/log")
@bp.doc("系统操作日志获取接口", "返回系统的操作日志")
# TODO:具体实现
def sys_log():
    return "hello"
