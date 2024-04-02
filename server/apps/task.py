# 任务管理接口
from apiflask import APIBlueprint
from apiflask.fields import String

bp = APIBlueprint("任务管理接口集合", __name__, url_prefix="/task")


# 创建任务接口
@bp.post("/create")
@bp.doc("")
@bp.input({
    "name": String(),
    "target": String()
})
# TODO：创建任务接口具体实现
def make_task():
    return {"msg": "ok"}


# 操作任务开始停止控制接口
@bp.post("/ops")
@bp.doc("")
# TODO：操作任务开始停止控制接口具体实现
def ops_task():
    pass


# 查询任务状态接口
@bp.get("/")
@bp.doc("")
# TODO：查询任务状态接口具体实现
def tasks_state():
    pass


# 任务详情接口
@bp.get("/<int:task_id>")
@bp.doc("")
# TODO：任务详情接口具体实现
def task_info():
    pass
