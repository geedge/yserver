import argparse
import ipaddress
import os.path
import platform
import socket

import ipinfo
import psutil
import requests
import yaml
from apiflask import APIFlask

from apps.delay import bp as delaybp
from apps.script import bp as scriptbp

# 注册蓝图
app = APIFlask(__name__, template_folder='./static/templates')
app.register_blueprint(delaybp)
app.register_blueprint(scriptbp)
# 代理配置
config = {}
# 代理类型参数映射表
atype_map = {
    "gjst": "攻击渗透",
    "csgz": "参数感知",
    "ztgz": "状态感知"
}


@app.get('/')
@app.doc("获取测试页面")
def hello():
    return "这是一个正常的测试页面"


# 获取代理的部署环境信息
def nodeinfo():
    # IP地址
    # IPv4地址通过向主控端发包时在主控端获取，从而定位最准确的IPv4地址（公网、内网）
    # IPv6地址获取本地的所有公网地址
    v6addr = []
    addr6_info_list = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    for a in addr6_info_list:
        addr = ipaddress.ip_address(a[4][0])
        if addr.is_global:
            v6addr.append(a[4][0])

    # 经纬度
    # 使用ipinfo.io进行定位，调用token
    token = "40e1b13cf6b35a"
    handler = ipinfo.getHandler(token)
    details = handler.getDetails()
    # 获取经纬度
    latlng = str(details.loc).split(",")
    lat, lng = latlng[0], latlng[1]

    # CPU核心数
    cpu_num = psutil.cpu_count()

    # 内存信息
    ram_size = int(psutil.virtual_memory().total / (1024 * 1024 * 1024))
    ram_per = psutil.virtual_memory().percent

    # 操作系统
    system = platform.system()
    #
    return {'v6addr': v6addr, 'lat': lat, 'lng': lng, 'cpu_num': cpu_num, 'ram_size': ram_size, 'ram_per': ram_per,
            'sys': system}


# 注册代理
def registernode(proto="http", port=2525, atype="gjst", server="127.0.0.1:8888"):
    info = nodeinfo()
    info["port"] = port
    info["atype"] = atype
    print(info)
    r = requests.post(proto + "://" + server + "/agent/register", json=info)
    if r.status_code != 200:
        print(r.status_code)
        print("注册失败，请检查参数配置是否正确")
        return
    return r.json()['id']


if __name__ == '__main__':
    # 判断是否已存在配置文件
    if os.path.exists("config.yaml"):
        # 存在则读取配置文件信息
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        app.run(host="0.0.0.0", port=config["port"], debug=True)
    else:
        # 不存在则解析命令行参数
        # 命令行参数设置
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", type=int, default=2525, help="代理的开放通信端口")
        parser.add_argument("-t", "--atype", type=str, default="gjst",
                            help="代理的工作类型 {gjst(攻击渗透) / csgz(参数感知) / ztgz(状态感知)}")
        parser.add_argument("-s", "--server", type=str, default="127.0.0.1:8888", help="主控端访问地址+端口号")

        # 解析参数
        args = parser.parse_args()

        # 注册代理，并获取主控分配的代理编号
        id = registernode(port=args.port, server=args.server, atype=args.atype)
        config = {"id": id, "port": args.port, "atype": args.atype, "server": args.server}

        # 配置写入yaml文件存储
        with open('config.yaml', 'w') as f:
            yaml.dump(config, f)

        # 运行
        app.run(host="0.0.0.0", debug=True, port=config["port"])
