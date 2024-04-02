# 目标状态感知
import random
# 时延测试接口
import threading

import pandas as pd
import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import Integer, String, List, Nested, IP, DateTime
from faker import Faker
from faker.providers import company
from requests.exceptions import Timeout

fake = Faker("zh_CN")
fake.add_provider(company)
bp = APIBlueprint("目标信息及状态接口集合", __name__, url_prefix="/target")

icmp_delaytable = {}
tcp_delaytable = {}
dns_delaytable = {}


class Target(Schema):
    ipv4 = String()
    ipv6 = String()
    protocol = List(String())
    protect = List(String())
    cou = String()
    isp = String()
    lat = String()
    lng = String()
    time = DateTime()


class TestNode(Schema):
    Id = Integer()
    Name = String()
    Ip = String()
    Loc = String()
    Port = Integer()


class Delay(Schema):
    Id = Integer()
    CurrDelay = String()
    # MeanDelay=Integer()
    # MaxDelay=Integer()
    Type = String()


class DelayOut(Schema):
    delay_data = List(Nested(Delay))


@bp.get("/delay/<string:type>")
@bp.doc("获取每个节点的时延数据", "type参数为{icmp,dns,tcp}中的一个")
@bp.input({"ip": IP(required=False)}, location="query")
@bp.output(DelayOut)
def get_pernode_delay(query_data, type):
    addr = ""
    if 'ip' in query_data.keys():
        addr = query_data['ip']
    ans = []
    threads = []
    df = pd.read_csv("./server.csv", encoding="utf-8")
    for index, row in df.iterrows():
        mythread = threading.Thread(target=task, args=[ans, addr, row, type])
        mythread.start()
        threads.append(mythread)
    for t in threads:
        t.join()
    return {'delay_data': ans}


threadLock = threading.Lock()


def task(ans, addr, row, type):
    if type == "icmp":
        res = icmp_delay_query(addr, row['ip'])
        threadLock.acquire()
        ans.append({
            'Id': row['id'],
            'CurrDelay': res,
            'Type': type})
        threadLock.release()
        return
    if type == "tcp":
        res = tcp_delay_query(addr, row['ip'])
        threadLock.acquire()
        ans.append({
            'Id': row['id'],
            'CurrDelay': res,
            'Type': type})
        threadLock.release()
        return
    if type == "dns":
        res = dns_delay_query(addr, row['ip'])
        threadLock.acquire()
        ans.append({
            'Id': row['id'],
            'CurrDelay': res,
            'Type': type})
        threadLock.release()


def icmp_delay_query(target, addr):
    try:
        res = requests.get(url="http://" + addr + ":2525/script/icmpdelay", params={'ip': target}, timeout=5)
        print("icmp ok:" + addr + "-------" + res.text + "-------" + str(res.elapsed.total_seconds()))
        icmp_delaytable[str(addr) + str(target)] = res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr) + str(target) in icmp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            icmp_delaytable[str(addr) + str(target)] = 0
        return icmp_delaytable[str(addr) + str(target)]


def tcp_delay_query(target, addr):
    try:
        res = requests.get(url="http://" + addr + ":2525/script/tcpdelay", params={'ip': target, 'port': 53}, timeout=5)
        print("tcp ok:" + addr + "-------" + res.text)
        tcp_delaytable[str(addr) + str(target)] = res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr) + str(target) in tcp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            tcp_delaytable[str(addr) + str(target)] = 0
        return tcp_delaytable[str(addr) + str(target)]


def dns_delay_query(target, addr):
    try:
        res = requests.get(url="http://" + addr + ":2525/script/dnsdelay", params={'ip': target}, timeout=5)
        print("dns ok:" + addr + "-------" + res.text)
        dns_delaytable[str(addr) + str(target)] = res.text
        return dns_delaytable[str(addr) + str(target)]
    except Timeout:
        # 如果存在旧数据
        if str(addr) + str(target) in dns_delaytable.keys():
            pass
        # 不存在则设0
        else:
            dns_delaytable[str(addr) + str(target)] = 0
        return dns_delaytable[str(addr) + str(target)]


# 状态感知——DNS记录测试接口
import dns.nameserver
from apiflask.fields import String
from apiflask.validators import OneOf
from dns import resolver


@bp.get("/check")
@bp.doc("通过指定的解析器获取指定域名的A/AAAA记录")
@bp.input({
    'rev': String(required=True),
    'domain': String(required=True),
    'qtype': String(required=True, validate=OneOf(['A', 'AAAA', "CNAME", "NS"]))
}, location='query')
def record(query_data):
    # 特殊协议头
    protols = ["https", "tls"]
    ans = []
    # 参数读取
    rev = query_data['rev']
    domain = query_data['domain']
    qtype = query_data['qtype']

    # 解析器配置
    myResolver = resolver.Resolver()
    # 根据rev参数配置解析器
    is_Do53 = any(proto if proto in rev else False for proto in protols)
    if not is_Do53:
        # 存在端口指定
        if ":" in rev:
            res = rev.split(":")
            myResolver.nameservers = [dns.nameserver.Do53Nameserver(res[0], port=res[1])]
        else:
            myResolver.nameservers = [rev]
    else:
        #  doh服务
        if "https" in rev:
            myResolver.nameservers = [dns.nameserver.DoHNameserver(url=rev)]
        # dot服务
        if "tls" in rev:
            res = rev.split("//")
            myResolver.nameservers = [dns.nameserver.DoTNameserver(address=res[1])]
    myAnswers = myResolver.resolve(domain, qtype)
    if myAnswers.rrset is not None:
        for r in myAnswers.rrset:
            ans.append({"rrset": str(r)})
    return {'ans': ans}


@bp.get("/")
@bp.doc("目标信息获取接口", "返回目标信息")
@bp.input({
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1)
}, location='query')
@bp.output({
    "data": List(Nested(Target()))
})
def target_info(query_data):
    per_page = query_data["per_page"]
    target_list = []

    for _ in range(per_page):
        lat, lng, _, cou, _ = fake.location_on_land()
        target_list.append({
            "ipv4": fake.ipv4_public(),
            "ipv6": fake.ipv6(),
            "protocol": random.choices(["IPv6", "DNSSEC", "DoH", "DoT"], k=random.randint(1, 4)),
            "protect": random.choices(["0x20", "端口随机化", "请求最小化", "DNSSEC验证"], k=random.randint(1, 4)),
            "cou": cou,
            "lat": lat,
            "lng": lng,
            "isp": fake.company(),
            "time": fake.date_time_between('-2y'),
        })

    return {"data": target_list}
