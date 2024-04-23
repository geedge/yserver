# 登录
from apiflask import APIBlueprint
from apiflask.fields import String, Integer

bp = APIBlueprint("登录退出接口集合", __name__, url_prefix="/login")


# 用户登录处理函数
@bp.post("/")
@bp.doc("登录接口",
        description="输入用户名和密码，返回响应码code，消息msg以及是否成功登陆标识status</br>若成功登录则msg返回用户编号")
@bp.input({
    "username": String(),
    "pwd": String()
})
@bp.output({
    # 响应码
    "code": Integer,
    # 返回消息
    "msg": String,
    # 是否成功登录
    "status": String,
})
# TODO:登录处理(For 石昊月师弟)
def login(json_data):
    pass


# 用户退出处理函数
@bp.post("/")
@bp.doc("退出登录接口", description="输入用户名和用户编号，返回响应码code，消息msg以及是否成功退出标识status")
@bp.input({
    "id": String(),
    "username": String()
})
@bp.output({
    # 响应码
    "code": Integer,
    # 返回消息
    "msg": String,
    # 是否成功退出
    "status": String,
})
# TODO:退出处理(For 石昊月师弟)
def logout(json_data):
    pass
