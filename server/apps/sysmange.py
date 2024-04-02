# 系统管理——用户管理
from apiflask import APIBlueprint

bp = APIBlueprint("系统管理接口集合", __name__, url_prefix="/user")


@bp.get("/")
@bp.doc("系统用户信息获取接口", description="返回当前系统中所有用户")
def list_user():
    user1 = {"name": "测试"}
    return {"code": 200}
