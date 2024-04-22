# 工具函数集合
import requests


# 代理输出回传
def agent_echo(proto, server, level, info):
    data = {"level": level, "info": info}
    r = requests.post(proto + "://" + server, json=data)
    if r.status_code == 200:
        print("ok")
