# 代理通信与注册接口
from apiflask import APIBlueprint
from apiflask.fields import String, Integer
from apiflask.validators import OneOf

bp = APIBlueprint("agent", __name__, url_prefix="/agent")


# 代理注册接口
@bp.post("/register", )
@bp.doc("代理注册接口", "返回分配给代理的编号值")
@bp.input({
    # 代理类型
    "type": String(required=True, validate=OneOf(["gjst", "mbgz", "ztgz"])),
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
@bp.doc("代理信息获取接口", hide=True)
# TODO:代理信息获取接口实现
def agent_info():
    return "ok"
