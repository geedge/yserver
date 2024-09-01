# 工具包
import ipaddress

from loguru import logger


def debug(message, *args, **kwargs):
    logger.debug(message, *args, **kwargs)


def info(message, *args, **kwargs):
    logger.info(message, *args, **kwargs)


def error(message, *args, **kwargs):
    logger.error(message, *args, **kwargs)


# 判断是否为IP地址，若是返回4(IPv4)或6(IPv6),否则返回None
def is_ipaddress(address: str):
    try:
        ip = ipaddress.ip_address(address)
        return int(ip.version)
    except ValueError:
        return None
