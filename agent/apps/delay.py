# 状态感知——时延测试
import random
import time

from apiflask import APIBlueprint
import dns.nameserver
from dns import resolver
from flask import Blueprint, request
from icmplib import ping

import apps.utiltcping as utping

bp = APIBlueprint("delay", __name__, url_prefix="/delay")


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
    tdelay = utping.cli(addr, port, 2, 1)
    return str(tdelay)


# dns时延测试函数，返回执行完成时的时间戳
@bp.route("/dns")
def dnsdelay():
    addr = request.args.get("ip")
    port = request.args.get("port", default=53)
    chinese_domains = [
    "baidu.com", "taobao.com", "jd.com", "qq.com", "163.com",
    "sina.com.cn", "sogou.com", "alipay.com", "tmall.com", "youku.com",
    "douban.com", "zhihu.com", "ifeng.com", "sohu.com", "ximalaya.com",
    "meituan.com", "58.com", "dianping.com", "ctrip.com", "iqiyi.com",
    "kuaishou.com", "tianya.cn", "vip.com", "mgtv.com", "bilibili.com",
    "xiaomi.com", "360.cn", "pinduoduo.com", "netease.com", "kaola.com",
    "huya.com", "douyin.com", "kuaidi100.com", "xueqiu.com", "zhaopin.com",
    "ganji.com", "hao123.com", "weibo.com", "jiayuan.com", "chinahr.com",
    "tencent.com", "yhd.com", "cnblogs.com", "hexun.com", "autohome.com.cn",
    "guokr.com", "ebrun.com", "csdn.net", "163yun.com", "taikang.com",
    "fang.com", "cnki.net", "fangdd.com", "suning.com", "ctrip.com",
    "2345.com", "jingdong.com", "eastmoney.com", "cfuniverse.com", "jumei.com",
    "iqiyi.com", "58.com", "zto.com", "ganji.com", "feigua.cn",
    "maitian.cn", "58pic.com", "chinamobile.com", "suning.com", "dangdang.com",
    "fang.com", "kaola.com", "hao123.com", "renren.com", "dangdang.com",
    "guokr.com", "anjuke.com", "dingtalk.com", "xiaohongshu.com", "zto.com",
    "smzdm.com", "pingan.com", "renren.com", "ganji.com", "momo.com",
    "beisen.com", "douyin.com", "toutiao.com", "pconline.com.cn", "jz5u.com",
    "360.com", "ce.cn", "12306.cn", "12306.com", "yihaodian.com",
    "maoyan.com", "baicaio.com", "cnbeta.com", "tuniu.com", "dxy.com"
    ]
    random_domain = random.choice(chinese_domains)
    domain = request.args.get("domain", default=random_domain)
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
