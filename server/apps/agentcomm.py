# 代理通信与注册接口
import random

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, List, Nested, Boolean, DateTime, Float
from apiflask.validators import OneOf
from flask import request

from settings import *
from .util import da, error

bp = APIBlueprint("代理管理接口集合", __name__, url_prefix="/agent")

# 代理类型
agent_type = ["攻击渗透", "状态感知", "参数感知"]

# 代理选项参数和代理类型的映射关系
agent_key_map = {"gjst": agent_type[0], "ztgz": agent_type[1], "csgz": agent_type[2]}

# 状态选项参数和值的映射关系
status_map = {1: True, 0: False}
idle_map = {1: True, 0: False}

# 数据库列与返回值的键对应关系
agent_response_map = {
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


# 代理注册接口
@bp.post("/register")
@bp.doc("代理注册接口", "返回分配给代理的编号值，用于代理和主控端通信注册，前端界面无需调用")
@bp.input({
    "atype": String(validate=OneOf(["gjst", "ztgz", "csgz"])),
    'v6addr': List(String()),
    'lat': String(),
    'lng': String(),
    'cpu_num': Integer(),
    'ram_size': Integer(),
    'ram_per': Float(),
    'sys': String(),
    "port": Integer()
}, example={'atype': "gjst", 'v6addr': ["2001::1"], 'lat': "-1.111", 'lng': "1.1111", 'cpu_num': 4,
            'ram_size': 16, 'ram_per': 0.55,
            'sys': "linux", "port": 2525})
# 参数说明
# 代理类型
# "type": String(required=True, validate=OneOf(["gjst", "mbgz", "ztgz"])),
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
def register_agent(json_data):
    data = dict(json_data)
    id = "".join(random.sample('1234567890zyxwvutsrqponmlkjihgfedcba', 8))
    # 代理所有参数
    param = {"id": id, "ipaddr": "|".join([request.remote_addr] + [i for i in data["v6addr"]]), "lat": data["lat"],
             "lng": data["lng"], "cpunum": data["cpu_num"], "mem": str(data["ram_size"]) + "GB" + "(" + str(
            '{:.2f}'.format(100 * (1 - float(data["ram_per"])))) + "%" + "可用)", "sys": data["sys"], "status": True,
             "idle": True, "port": data["port"], "atype": data["atype"], "tab": MYSQL_TAB_AGENT}
    # 数据库表名

    # 插入记录
    err = insert_agent(param)
    if not err:
        return {"id": id}
    else:
        return {"code": 500, "err": err}


# 代理任务下发
# TODO:具体实现
def deliver_task(agent_id, policy, policy_param):
    # 查询agent_id对应代理的ip和端口信息
    # 将policy和policy_param作为参数传递到对应接口
    pass
    return None


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
    VALUES('%s','%s','%s','%s')
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
    "atype": String(load_default="all", validate=OneOf(["all", "gjst", "ztgz", "csgz"])),
    "status": Integer(load_default=2, validate=OneOf([0, 1, 2])),
    "idle": Integer(load_default=2, validate=OneOf([0, 1, 2])),
    "page": Integer(load_default=1),
    "per_page": Integer(load_default=10)
}, location="query")
@bp.output({
    "code": Integer(),
    "agent_data": List(Nested(agent())),
    "total": Integer()
})
def agent_info(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]
    agent_type = query_data["atype"]
    status = query_data["status"]
    idle = query_data["idle"]

    # 代理信息列表
    agent_list = []
    res = da.get_data(data_type="agent", search={"atype": agent_type, "status": status, "idle": idle},
                      offset=(page - 1) * per_page, limit=per_page)
    res_count = da.count_data(data_type="agent", search={"atype": agent_type, "status": status, "idle": idle})
    for r in res:
        agent = {}
        for key, value in r.items():
            agent[agent_response_map[key]] = value if key != "IPADDR" else str(value).split("|")
        agent_list.append(agent)
    return {"code": 200, "agent_data": agent_list, "total": res_count}


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
def del_agent(json_data):
    print(json_data)
    sql = """DELETE FROM %s WHERE AGENT_ID = '%s'
    """ % (MYSQL_TAB_AGENT, json_data["id"])
    try:
        da.cursor.execute(sql)
        da.conn.commit()
    except Exception as e:
        error(message=str(e))
        return {"code": 500, "msg": str(e)}
    return {"code": 200, "msg": "ok"}


# 代理信息存储到数据库
def insert_agent(param: dict):
    sql = """REPLACE INTO %(tab)s(
            AGENT_ID,
            IPADDR,
            LAT,
            LNG ,
            AGENT_TYPE,
            SYS ,
            PORT ,
            CPU_NUM ,
            STATUS ,
            MEM,
            IDLE) 
            VALUES(
            '%(id)s',
            '%(ipaddr)s',
            '%(lat)s',
            '%(lng)s',
            '%(atype)s',
            '%(sys)s',
            '%(port)s',
            '%(cpunum)s',
            '%(status)s',
            '%(mem)s',
            '%(idle)s)';""" % param
    try:
        da.cursor.execute(sql)
        da.conn.commit()
    except Exception as e:
        error(message=str(e))
        return e
    return None
