# 代理通信与注册接口
import random

import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, List, Nested, Boolean, DateTime, Float
from apiflask.validators import OneOf
from flask import request

from settings import *
from .util import error

from model import Agent,TaskLog
from exts import db
from sqlalchemy.exc import SQLAlchemyError

bp = APIBlueprint("代理管理接口集合", __name__, url_prefix="/agent")


class AgentOutput(Schema):
    id = String()
    ipaddr = List(String())
    atype = String(validate=OneOf(["攻击渗透", "状态感知", "参数感知"]))
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
        return {"code": 200, "msg": "ok", "id":agent.agent_id}
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
        agent = db.session.query(Agent).get(agent_id)
        ip, port = agent.ipaddr.split("|")[0], agent.port
        try:
            res = requests.post("http://%s:%s/script" % (ip, port), timeout=3,
                                json={'policy': policy, 'param': policy_param})
            if res.status_code == 200:
                return None
            error("任务分发错误，code: " + str(res.status_code) + " err: " + str(res.text))
            return res.text
        except Exception as e:
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
    agent_list = []
    query = db.session.query(Agent)
    if agent_type != "all":
        query = query.filter(Agent.agent_type == agent_type)
    if status != 2:
        query = query.filter(Agent.status == bool(status))
    if idle != 2:
        query = query.filter(Agent.idle == bool(idle))
    # 分页
    agents = query.offset((page - 1) * per_page).limit(per_page).all()
    # 查询总数
    agent_count = query.count()
    for agent in agents:
        agent_r = {}
        agent_r["id"] = agent.agent_id
        agent_r["ipaddr"] = agent.ipaddr.split("|") if agent.ipaddr else []
        agent_r["atype"] = agent.agent_type
        agent_r["status"] = agent.status
        agent_r["idle"] = agent.idle
        agent_r["port"] = agent.port
        agent_r["sys"] = agent.sys
        agent_r["cpu_num"] = agent.cpu_num
        agent_r["mem"] = agent.mem
        agent_r["start_time"] = agent.start_time
        agent_list.append(agent_r)
    return {"code": 200, "agent_data": agent_list, "total": agent_count}


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
