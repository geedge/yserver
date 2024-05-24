# 登录
from apiflask import APIBlueprint
from apiflask.fields import String, Integer, Boolean

from model import User
from exts import db

bp = APIBlueprint("登录退出接口集合", __name__, url_prefix="/auth")

# TODO 使用cookie

# 用户登录处理函数
@bp.post("/login")
@bp.doc("登录接口",
        description="输入用户名和密码，返回响应码code，消息msg以及是否成功登陆标识status</br>若成功登录则msg返回用户编号")
@bp.input({
    "username": String(),
    "pwd": String()
})
@bp.output({
    # 响应码
    "code": Integer(),
    # 返回消息
    "msg": String(),
    # 是否成功登录
    "status": Boolean(),
})

def login(json_data):
    users = db.session.execute(db.select(User).filter_by(user_name=json_data["username"])).scalars()
    for user in users:
        if user.user_pwd_hash == json_data["pwd"]:
            return {"code":200, "status":True, "msg":user.user_id}
    return {"code":200, "status":False, "msg":""}


# 用户退出处理函数
@bp.post("/logout")
@bp.doc("退出登录接口", description="输入用户名和用户编号，返回响应码code，消息msg以及是否成功退出标识status")
@bp.input({
    "id": String(),
    "username": String()
})
@bp.output({
    # 响应码
    "code": Integer(),
    # 返回消息
    "msg": String(),
    # 是否成功退出
    "status": Boolean(),
})
def logout(json_data):
    return {
        "code": 200,
        "msg":"退出成功",
        "status":True
    }