import argparse

from apiflask import APIFlask, Schema
from apiflask.fields import List, Nested

from agent.apps.datacheck import bp as checkbp
from agent.apps.delay import bp as scriptbp
from apps.agentcomm import bp as agentbp
from apps.delay import bp as delaybp, TestNode
from apps.task import bp as taskbp

# 注册蓝图
app = APIFlask(__name__, template_folder='./static/templates')
app.register_blueprint(checkbp)
app.register_blueprint(delaybp)
app.register_blueprint(scriptbp)
app.register_blueprint(agentbp)
app.register_blueprint(taskbp)


@app.get('/')
@app.doc("获取测试页面")
def hello():
    return "这是一个正常的测试页面"


class AllNode(Schema):
    nodes = List(Nested(TestNode))


# 获取所有节点的信息
# @app.get('/allnode')
# @app.doc("节点信息获取接口", "返回当前所有探测节点的信息")
# @app.output(AllNode)
# def nodeinfo():
#     df = pd.read_csv("./server.csv", encoding="utf-8")
#     ans = []
#     for index, row in df.iterrows():
#         ans.append({
#             'Id': row['id'],
#             'Name': row['name'],
#             'Ip': row['ip'],
#             'Loc': row['loc'],
#             'Port': row['port']})
#     return {'nodes': ans}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=2525, help="主控服务的开放通信端口")
    args = parser.parse_args()
    app.run(host="0.0.0.0", debug=True, port=args.port)
