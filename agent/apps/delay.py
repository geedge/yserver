# 状态感知——时延测试
import time

import apps.utiltcping as utping
import dns.nameserver
from dns import resolver
from flask import Blueprint, request
from icmplib import ping

bp = Blueprint("delay", __name__, url_prefix="/delay")


@bp.route("/test")
def hello():
    return "hello"


# icmp时延测试
@bp.route("/icmp")
def icmpdelay():
    addr = request.args.get("ip")
    host = ping(addr, count=2, interval=0.1, timeout=2)
    return str(host.avg_rtt)


@bp.route("/tcp")
def tcpdelay():
    addr = request.args.get("ip")
    port = request.args.get("port", default=53)
    tdelay = utping.cli(addr, port, 2, 2)
    return str(tdelay)


# dns时延测试函数，返回执行完成时的时间戳
@bp.route("/dns")
def dnsdelay():
    addr = request.args.get("ip")
    port = request.args.get("port", default=53)
    domain = request.args.get("domain", default="www.baidu.com")
    qtype = request.args.get("qtype", default="A")

    start_time = time.time()
    # 解析器配置
    myResolver = resolver.Resolver()
    myResolver.nameservers = [dns.nameserver.Do53Nameserver(addr, port=port)]

    # 开始解析
    ans = myResolver.resolve(domain, qtype, lifetime=4)
    stop_time = time.time()
    t = stop_time - start_time
    return str(format(t * 1000, ".3f"))
