# 工具函数集合
import requests
from loguru import logger


# 代理输出回传
def agent_echo(proto, server, level, info):
    data = {"level": level, "info": info}
    r = requests.post(proto + "://" + server, json=data)
    if r.status_code == 200:
        print("ok")


def debug(message, *args, **kwargs):
    logger.debug(message, *args, **kwargs)


def info(message, *args, **kwargs):
    logger.info(message, *args, **kwargs)


def error(message, *args, **kwargs):
    logger.error(message, *args, **kwargs)
