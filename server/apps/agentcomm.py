# 代理通信与注册接口
import random

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, List, Nested, Boolean, DateTime
from apiflask.validators import OneOf

from apps.util import fake

bp = APIBlueprint("代理管理接口集合", __name__, url_prefix="/agent")

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


# 代理注册接口
@bp.post("/register", )
@bp.doc("代理注册接口", "返回分配给代理的编号值", hide=True)
@bp.input({
    # 代理类型
    "type": String(required=True, validate=OneOf(["gjst", "csgz", "ztgz"])),
    # 代理的通信端口
    "port": Integer(required=True),
    # 代理所在的操作系统
    "sys": String()
})
def register_agent(query_data):
    print(query_data)


# 代理任务下发
def deliver_task():
    pass


# 代理输出接收
@bp.post("/res")
@bp.doc("代理输出消息接收接口", hide=True)
# TODO:代理输出接收接口实现
def task_ret():
    return "ok"


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
def agent_info(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]
    agent_list = []
    # TODO:接口数据库贯通实现
    for i in range(per_page):
        agent_list.append({
            "id": fake.unique.random_int(),
            "ipaddr": [fake.ipv4_public(), fake.ipv6()],
            "atype": fake.word(ext_word_list=agent_type),
            "status": random.choice([True, False]),
            "idle": random.choice([True, False]),
            "port": random.randint(1000, 65534),
            "sys": random.choice(["Linux", "Windows", "Macos"]),
            "cpu_num": 4,
            "mem": random.choice(["4", "8", "16", "32"]) + "GB(" + str(
                '{:.2f}'.format(100 * random.random())) + "%可用)",
            "start_time": fake.date_time_between(start_date="-1y")})

    return {"code": 200, "agent_data": agent_list, "total": 10 * per_page}


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
    return {"code": 200, "msg": "ok"}
