import argparse

from apiflask import APIFlask

from apps.agentcomm import bp as agentbp
from apps.sysinfo import bp as sysbp
from apps.sysmange import bp as mangbp
from apps.target import bp as targetbp
from apps.task import bp as taskbp

# 注册蓝图
app = APIFlask(__name__, template_folder='./static/templates')
# 目标状态获取接口
app.register_blueprint(targetbp)
# 代理接口
app.register_blueprint(agentbp)
# 任务管理接口
app.register_blueprint(taskbp)
# 系统管理接口
app.register_blueprint(mangbp)
# 系统状态获取接口
app.register_blueprint(sysbp)


@app.get('/')
@app.doc("获取测试页面")
def hello():
    return "这是一个正常的测试页面"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=12525, help="主控服务的开放通信端口")
    args = parser.parse_args()
    app.run(host="0.0.0.0", debug=True, port=args.port)
