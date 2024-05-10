# 目标状态感知
import random
# 时延测试接口
import threading

import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import Integer, String, List, Nested, IP, DateTime, Dict
from apiflask.validators import OneOf
from requests.exceptions import Timeout

from .util import fake

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
    Lat = String()
    Lng = String()
    # Port = Integer()


# 地图国家数据格式
class CouInfo(Schema):
    # 国家名称
    name = String()
    # 不同协议的解析器详细数量说明
    title = String()
    # 总数量
    value = Integer()


# 地图响应数据格式
class MapInfo(Schema):
    earthAddTitle = List(Nested(CouInfo()))


class Delay(Schema):
    Id = String()
    CurrDelay = Integer()
    # MeanDelay=Integer()
    # MaxDelay=Integer()
    Type = String()


class DelayOut(Schema):
    code = Integer()
    delay_data = List(Nested(Delay()))


@bp.get("/nodes")
@bp.doc("参与探测的节点信息获取接口", "传入任务编号taskid")
@bp.input({
    "taskid": String(required=True)
}, location="query")
@bp.output({
    "code": Integer(),
    "nodes": List(Nested(TestNode()))
})
def get_nodes(query_data):
    node_list = []
    num = 10
    for i in range(num):
        city=fake.province()
        geo_info = fake.local_latlng(country_code='CN')
        node_list.append({
            "Id": str(i),
            "Name": "测试节点"+str(i),
            "Ip": fake.ipv4(),
            "Loc": city,
            "Lat": geo_info[0],
            "Lng": geo_info[1],
        })
    return {"code": 200, "nodes": node_list}


@bp.get("/delay")
@bp.doc("获取每个节点的时延数据,单位为ms", "type参数为{icmp,dns,tcp}中的一个,target为目标IP或DoH目标域名")
@bp.input({
    "target": String(required=True),
    "type": String(required=True, validate=OneOf(["icmp", "dns", "tcp"]))}, location="query")
@bp.output(DelayOut)
def get_pernode_delay(query_data):
    target = query_data["target"]
    scan_type = query_data["type"]
    ans = []
    # threads = []
    # # df = pd.read_csv("./server.csv", encoding="utf-8")
    # for index, row in df.iterrows():
    #     # mythread = threading.Thread(target=task, args=[ans, target, row, scan_type])
    #     mythread.start()
    #     threads.append(mythread)
    # for t in threads:
    #     t.join()
    for i in range(10):
        ans.append({"Id": str(i), "Type": scan_type, "CurrDelay": random.randint(1, 1000)})
    return {"code": 200, 'delay_data': ans}


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

rrest_key = "rrset"
# 协议类型
proto_type = ['IPv6', 'DNSSEC', "DoH", "DoT"]


@bp.get("/check")
@bp.doc("通过指定的解析器获取指定域名的A/AAAA/CNAME/NS记录","rev参数可选范围:{114.114.114.114,223.5.5.5,8.8.8.8,119.29.29.29}")
@bp.input({
    'rev': String(required=True),
    'domain': String(required=True),
    'qtype': String(required=True, validate=OneOf(['A', 'AAAA', "CNAME", "NS"]))
}, location='query')
@bp.output({
    "code": Integer(),
    "ans": List(Dict(String(validate=OneOf([rrest_key])), String()))
})
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
            myResolver.nameservers = [dns.nameserver.Do53Nameserver(rev)]
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
            ans.append({rrest_key: str(r)})
    return {"code": 200, 'ans': ans}


@bp.get("/")
@bp.doc("(表格)目标信息获取接口", "返回目标信息")
@bp.input({
    "protocol": String(validate=OneOf(['IPv6', 'DNSSEC', "DoH", "DoT"])),
    "cou": String(),
    "isp": String(),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1),
    "ip": IP(load_default=None)
}, location='query')
@bp.output({
    "code": Integer(),
    "data": List(Nested(Target())),
    "total": Integer()
})
def target_info(query_data):
    # 普通检索
    if query_data["ip"] is None:
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
        return {"code": 200, "data": target_list, "total": 10 * per_page}
    # 查询目标
    else:
        lat, lng, _, cou, _ = fake.location_on_land()
        target = [{"ipv4": query_data["ip"],
                   "ipv6": fake.ipv6(),
                   "protocol": random.choices(["IPv6", "DNSSEC", "DoH", "DoT"], k=random.randint(1, 4)),
                   "protect": random.choices(["0x20", "端口随机化", "请求最小化", "DNSSEC验证"],
                                             k=random.randint(1, 4)),
                   "cou": cou,
                   "lat": lat,
                   "lng": lng,
                   "isp": fake.company(),
                   "time": fake.date_time_between('-2y'), }]
        return {"code": 200, "data": target, "total": 1}


@bp.get("/filter")
@bp.doc("目标可筛选信息获取接口")
@bp.output({
    "code": Integer(),
    "proto": List(String()),
    "isp": List(String()),
    "cou": List(String())
})
def filter_info():
    proto = proto_type
    isp = ["google", "cloudflare", "阿里云", "DNSPod", "quad9"]
    cou = ["美国", "中国", "日本", "澳大利亚", "新加坡"]
    return {"code": 200, "proto": proto, "isp": isp, "cou": cou}


@bp.get("/map")
@bp.doc("地图信息获取接口")
@bp.input({
    "protocol": String(load_default=None, validate=OneOf(proto_type)),
    "cou": String(load_default=None),
    "isp": String(load_default=None),
    "ip": IP(load_default=None)
}, location="query")
@bp.output({
    "code": Integer(),
    "dataObject": Dict(String(load_default="earthAddTitle"), List(Nested(CouInfo()))),
})
def map_info(query_data):
    if query_data["ip"] is None:
        cou_list = []
        cou_num = 197 if query_data["cou"] is None else 1
        for _ in range(cou_num):
            # 每种协议的解析器数量
            value_list = [random.randint(1, 5000) if proto_type[i] == query_data["protocol"] else 0 for i in
                          range(len(proto_type))] if query_data["protocol"] is not None else [random.randint(1, 5000)
                                                                                              for _ in
                                                                                              range(len(proto_type))]
            cou_list.append({
                "name": fake.unique.country() if query_data["cou"] is None else query_data["cou"],
                "title": "各类解析器数量为：{IPv6：" + str(value_list[0]) + "，DNSSEC：" + str(
                    value_list[1]) + "，DoH：" + str(value_list[2]) + "，DoT：" + str(value_list[3]) + "}",
                "value": sum(value_list),
            })
        fake.unique.clear()
        return {"code": 200, "dataObject": {"earthAddTitle": cou_list}}
    # 查询目标
    else:
        target = [{"name": fake.unique.country(),
                   "title": "该解析器支持：" + '、'.join(random.choices(proto_type, k=random.randint(1, 4))) + " 协议",
                   "value": 1, }]
        return {"code": 200, "dataObject": {"earthAddTitle": target}}
