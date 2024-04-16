# 代理通信与注册接口
import random

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, List, Nested, Boolean, DateTime
from apiflask.validators import OneOf
from flask import request

from settings import *
from .util import da

bp = APIBlueprint("代理管理接口集合", __name__, url_prefix="/agent")

# 代理类型
agent_type = ["渗透攻击", "状态感知", "参数感知"]


class agent(Schema):
    id = String()
    ipaddr = List(String())
    atype = String(validate=OneOf(agent_type))
    status = Boolean()
    idle = Boolean()
    port = Integer()
    sys = String()
    cpu_num = Integer()
    mem = String()
    start_time = DateTime()


# 数据库列与返回值的键对应关系
agent_map = {
    "AGENT_ID": "id",
    "IPADDR": "ipaddr",
    "START_TIME": "start_time",
    "LAT": "lat",
    "LNG": "lng",
    "AGENT_TYPE": "atype",
    "SYS": "sys",
    "PORT": "port",
    "CPU_NUM": "cpu_num",
    "STATUS": "status",
    "IDLE": "idle",
    "MEM": "mem"
}


# 代理注册接口
@bp.post("/register")
@bp.doc("代理注册接口", "返回分配给代理的编号值", hide=True)
# 参数说明
# 代理类型
# "type": String(required=True, validate=OneOf(["stgj", "mbgz", "ztgz"])),
# 代理的通信端口
# "port": Integer(required=True),
# # 代理所在的操作系统
# "sys": String(),
# # IPv6地址
# # "v6addr": List(String()),
# # 经度
# "lat": String(),
# # 纬度
# "lng": String(),
# # cpu核心数
# "cpu_num": Integer(),
# # 内存大小
# "ram_size": Integer(),
# # 已用内存比例
# "ram_per": Float()
def register_agent():
    data = dict(request.json)
    id = "".join(random.sample('1234567890zyxwvutsrqponmlkjihgfedcba', 8))
    # 代理所有参数
    param = {"id": id,
             "ipaddr": (request.remote_addr).join(("|" + i) for i in data["v6addr"]),
             "start_time": str(datetime.datetime.now()),
             "lat": data["lat"],
             "lng": data["lng"],
             "cpunum": data["cpu_num"],
             "mem": data["ram_size"] + "GB" + "(" + {1 - data["ram_per"]} + "%" + "可用)",
             "sys": data["sys"],
             "status": True,
             "idle": True,
             "port": data["port"],
             "atype": data["atype"],
             }
    err = insert_agent(param)
    if not err:
        return {"id": id}


# 代理任务下发
def deliver_task(agent_id, policy, policy_param):
    # TODO:具体实现
    # 查询agent_id对应代理的ip和端口信息
    # 将policy和policy_param作为参数传递到对应接口
    pass


@bp.post("/res")
@bp.doc("代理输出消息接收接口", hide=True)
def task_ret(json_data):
    """
    task_ret 代理输出信息接收

    Arguments:
        json_data -- 请求中的json内容，必须包含"id"、"taskpolicy"、"level"和"info"两个keyword

    Returns:
        "ok" -- 成功执行
    """
    sql = """INSERT INTO %s(CREATED_BY_AGENT,TLOG_LEVEL,TLOG_INFO,TLOG_TP)
    VALUES(%s,%s,%s,%s)
    """ % (MYSQL_TAB_TASK_LOG, json_data["id"], json_data["level"], json_data["info"],
           json_data["taskpolicy"])
    try:
        da.cursor.execute(sql)
        da.conn.commit()
        return "ok"
    except Exception as e:
        print(e)


@bp.get("/")
@bp.doc("代理信息获取接口", description="输入参数说明：</br>"
                                        + "atype:能力类型，可选参数范围及对应含义为：all-全部（默认），gjst-攻击渗透，ztgz-状态感知，csgz-参数感知 </br>"
                                        + "status:当前状态，可选参数范围及对应含义为：2-全部(默认)，1-在线，0-离线 </br>"
                                        + "idle:是否空闲，可选参数范围及对应含义为：2-全部(默认)，1-空闲，0-执行中 </br>")
@bp.input({
    "atype": String(load_default="all"),
    "status": Integer(validate=OneOf([0, 1, 2])),
    "idle": Integer(validate=OneOf([0, 1, 2])),
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10)
}, location="query")
@bp.output({
    "code": Integer(),
    "agent_data": List(Nested(agent())),
    "total": Integer()
})
# TODO: code total
def agent_info(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]
    agent_list = []
    res = da.get_data(data_type="agent", offset=(page - 1) * per_page, limit=per_page)
    for r in res:
        agent = {}
        for key, value in r.items():
            agent[agent_map[key]] = value if key != "IPADDR" else str(value).split("|")
        agent_list.append(agent)
    return {"code": 200, "agent_data": agent_list, "total": 100}


# 代理信息存储到数据库
def insert_agent(param: dict):
    sql = """REPLACE INTO %s(AGENT_ID,IPADDR,
            CREATED_TIME,
            LAT,
            LNG ,
            AGENT_TYPE,
            SYS ,
            PORT ,
            CPU_NUM ,
            STATUS ,
            RAM_SIZE ,
            WORK_STATUS) VALUES(
                %(id)s,
                %(ipaddr)s,
                %(create_time)s,
                %(lat)s,
                %(lng)s,
                %(atype)s,
                %(sys)s,
                %(port)s,
                %(cpunum)s,
                %(status)s,
                %(mem)s,
                %(work_status)s)
            )""" % param
    da.cursor.execute(sql)
    da.conn.commit()
    return None


@bp.doc("代理删除接口", "输入参数说明：</br>"
        + "id: 代理编号")
@bp.post("/del")
@bp.input({
    "id": String(required=True)
})
@bp.output({
    "code": Integer(),
    "msg": String()
})
# TODO: 实现
def del_agent(json_data):
    print(json_data)
    return {"code": 200, "msg": "ok"}
