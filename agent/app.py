import argparse
import platform

import requests
from apiflask import APIFlask, Schema, PaginationSchema
from apiflask.fields import List, Nested
from flask import request
from apps.script import bp as scriptbp
import psutil
import geocoder
import socket
import ipaddress

import pandas as pd

# 注册蓝图
app = APIFlask(__name__, template_folder='./static/templates')
app.register_blueprint(scriptbp)


@app.get('/')
@app.doc("获取测试页面")
def hello():
    return "这是一个正常的测试页面"


# 获取代理的部署环境信息
def nodeinfo():
    # IP地址
    ## IPv4地址通过向主控端发包时在主控端获取，从而定位最准确的IPv4地址（公网、内网）
    ## IPv6地址获取本地的所有公网地址
    v6addr = []
    addr6_info_list = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    for a in addr6_info_list:
        addr = ipaddress.ip_address(a[4][0])
        if addr.is_global:
            v6addr.append(a[4][0])

    # 经纬度
    g = geocoder.ip('me')
    lat, lng = g.lat, g.lng

    # CPU核心数
    cpu_num = psutil.cpu_count()

    # 内存信息
    ram_size = psutil.virtual_memory().total
    ram_per = psutil.virtual_memory().percent

    # 操作系统
    system = platform.system()
    #
    return {'v6addr': v6addr, 'lat': lat, 'lng': lng, 'cpu_num': cpu_num, 'ram_size': ram_size, 'ram_per': ram_per,
            'system': system}


# 注册代理
def registernode(port=2525,atype="stgj",server="127.0.0.1:8888"):
    info=nodeinfo()
    info["port"]=port
    info["type"]=atype
    requests.post("http://"+server)


if __name__ == '__main__':
    # 命令行参数设置
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=2525, help="代理的开放通信端口")
    parser.add_argument("-t", "--type", type=str, default="stgj", help="代理的工作类型 {stgj(渗透攻击) / mbgz(目标感知) / ztgz(状态感知)}")
    parser.add_argument("-s", "--server", type=str, default="127.0.0.1:8888",help="主控端访问地址+端口号")
    args = parser.parse_args()
    registernode(args.port,server=args.server)

    app.run(host="0.0.0.0", debug=True, port=args.port)
