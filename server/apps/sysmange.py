# 系统管理——用户管理

from apiflask import APIBlueprint
from apiflask.fields import String, Integer, List, Dict

from .util import error
from model import User, model_to_dict_list
from exts import db
bp = APIBlueprint("系统管理接口集合", __name__, url_prefix="/user")


@bp.get("/")
@bp.doc("系统用户信息获取接口", description="返回当前系统中所有用户")
@bp.input({
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location='query')
@bp.output({
    "code": Integer(),
    "data": List(Dict()),
    "total": Integer()

})
def list_user(query_data):
    page_limit = User.query.paginate(page = query_data['page'],per_page=query_data['per_page']).items
    users = model_to_dict_list(page_limit)
    return {"code": 200, "data": users, "total":len(users)}


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
    # TODO 用户组
    us = User(
        user_id = json_data["account"],
        user_name = json_data["username"],
        created_by = json_data["cur_user"],
        user_pwd_hash = json_data["pwd"],
        user_group = 'normal'
    )
    try:
        db.session.add(us)
        db.session.commit()
    except Exception as e:
        error(message=str(e))
        return e
    return {"code": 200, "msg": "ok"}
