from apiflask import APIFlask
from flask_cors import CORS

import settings
from apps.agentcomm import bp as agentbp
from apps.login import bp as loginbp
from apps.sysinfo import bp as sysbp
from apps.sysmange import bp as mangbp
from apps.target import bp as targetbp
from apps.task import bp as taskbp
from exts import db

# 注册蓝图
app = APIFlask(__name__, template_folder='./static/templates')
# 跨域支持
CORS(app, origins='*')
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
# 登录退出接口
app.register_blueprint(loginbp)

app.config[
    "SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://root:{settings.MYSQL_PAWD}@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DATADB}"
db.init_app(app)


@app.get('/')
@app.doc("获取测试页面")
def hello():
    return "这是一个正常的测试页面"


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=settings.DEBUG, port=settings.SERVER_PORT)
