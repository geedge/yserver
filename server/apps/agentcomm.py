# 代理通信与注册接口
import random
import string

import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, List, Nested, Boolean, DateTime, Float
from apiflask.validators import OneOf
from flask import request

from settings import *
from .util import da, error

from model import Agent,TaskLog
from exts import db
from sqlalchemy.exc import SQLAlchemyError

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


class AgentOutput(Schema):
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
    agent = Agent(
        agent_id = "".join(random.sample('1234567890zyxwvutsrqponmlkjihgfedcba', 8)),
        ipaddr = "|".join([request.remote_addr] + [i for i in data["v6addr"]]),
        lat = data["lat"],
        lng = data["lng"],
        agent_type = data["atype"],
        sys = data["sys"],
        port = data["port"],
        cpu_num = data["cpu_num"],
        status = True,
        mem = str(data["ram_size"]) + "GB" + "(" + str('{:.2f}'.format(100 * (1 - float(data["ram_per"])))) + "%" + "可用)",
        idle = True
    )
    try:
        db.session.add(agent)
        db.session.commit()
        return {"code": 200, "msg": "ok"}
    except SQLAlchemyError as e:
        db.session.rollback()
        error(str(e))
        return {"code": 500, "msg": str(e)}


# 代理任务下发
def deliver_task(agent_id, policy, policy_param):
    if policy == "ops":
        # TODO:控制代理
        return None
    else:
        # 查询agent_id对应代理的ip和端口信息
        sql = """
        SELECT IPADDR, PORT
        FROM %s
        WHERE AGENT_ID = '%s'
        """ % (MYSQL_TAB_AGENT, agent_id)
        da.conn.ping(reconnect=True)
        da.cursor.execute(sql)
        data = da.cursor.fetchall()

        # 解析代理的ipv4地址和通信端口
        # 如果代理有多个地址，则会以"|"分隔，详见register_agent函数
        # 第一个永远是ipv4地址（在代理向ipv4地址的端口注册信息的前提下），详见register_agent函数
        ip, port = str(data[0]['IPADDR']).split("|")[0], data[0]['PORT']

        # 将policy和policy_param作为参数传递到对应接口
        try:
            res = requests.post("http://%s:%s/script" % (ip, port), timeout=3,
                                json={'policy': policy, 'param': policy_param})
            if res.status_code == 200:
                return None
            error("任务分发错误，code: " + str(res.status_code) + " err: " + str(res.text))
            return res.text
        except Exception as e:
            if RUN_DEV:
                return None
            else:
                error(str(e))
                return str(e)


@bp.post("/res")
@bp.doc("代理输出消息接收接口", hide=True)
@bp.input({
    "id" : String(),
    "taskpolicy" : Integer(),
    "level" : String(validate=OneOf(["INFO", "WARNING", "ERROR"])),
    "info" : String()
})
def task_ret(json_data):
    task_log = TaskLog(
            created_by_agent = json_data["id"],
            tlog_level = json_data["level"],
            tlog_info = json_data["info"],
            tlog_tp = json_data["taskpolicy"]
    )
    try:
        db.session.add(task_log)
        db.session.commit()
        return {"code": 200, "msg": "ok"}
    except SQLAlchemyError as e:
        db.session.rollback()
        error(str(e))
        return {"code": 500, "msg": str(e)}


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
    "agent_data": List(Nested(AgentOutput())),
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
    try:
        agent = db.session.query(Agent).get(json_data["id"])
        if agent:
            db.session.delete(agent)
            db.session.commit()
            return {"code": "200", "msg": "代理删除成功"}
        else:
            return {"code": "404", "msg": "该代理id未找到！"}
    except SQLAlchemyError as e:
        db.session.rollback()
        error(str(e))
        return {"code": 500, "msg": str(e)}
