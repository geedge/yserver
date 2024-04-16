# 系统管理——用户管理

from apiflask import APIBlueprint, Schema
from apiflask.fields import String, Integer, DateTime, List, Nested

from apps.util import fake

bp = APIBlueprint("系统管理接口集合", __name__, url_prefix="/user")


class User(Schema):
    account = String()
    username = String()
    time = DateTime()
    created_by = String()
    group = String()


@bp.get("/")
@bp.doc("系统用户信息获取接口", description="返回当前系统中所有用户")
@bp.input({
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location='query')
@bp.output({
    "code": Integer(),
    "data": List(Nested(User()))
})
def list_user(query_data):
    if query_data['page'] == 1:
        user_list = [
            {"account": "Root", "username": "管理员", "time": fake.date_time_between(start_date='-10y', end_date='-9y'),
             "created_by": "", "group": "Admin"}]
    else:
        user_list = []
    for _ in range(query_data["per_page"] - len(user_list)):
        user_list.append({
            "account": fake.vin(),
            "username": fake.name(),
            "time": fake.date_time_between("-1y"),
            "created_by": "管理员",
            "group": "Admin"
        })
    return {"code": 200, "data": user_list}


@bp.post("/")
@bp.doc("系统用户创建接口", description="接收参数包括 用户姓名、新帐户名、新用户密码以及当前执行该注册操作的账户名")
@bp.input({
    "username": String(),
    "account": String(required=True),
    "pwd": String(required=True),
    "cur_user": String(load_default="Root")
})
@bp.output({
    "code": Integer(),
    "msg": String()
})
def create_user(json_data):
    print(json_data)
    return {"code": 200, "msg": "ok"}
