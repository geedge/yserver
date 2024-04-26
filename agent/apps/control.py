# 控制当前代理行为
from apiflask import APIBlueprint

bp = APIBlueprint('代理操作接口集合', __name__, url_prefix='/ops')


@bp.get("/")
def ctl_agent(query_data):
    pass
