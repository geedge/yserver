# 目标状态感知
# 时延测试接口
import ipaddress
import json
import random
import threading
import asyncio
from operator import or_
from concurrent.futures import ThreadPoolExecutor
from flask import current_app
import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import Integer, String, List, Nested, IP, DateTime, Dict, Float
from apiflask.validators import OneOf
from requests.exceptions import Timeout
from sqlalchemy import and_, distinct, func, case

from apps.util import debug, is_ipaddress
from exts import db, scheduler
from model import Policy, Target, Task, Agent, TargetStatus, TaskPolicy

from sklearn.cluster import KMeans, MiniBatchKMeans
import numpy as np

bp = APIBlueprint("目标信息及状态接口集合", __name__, url_prefix="/target")

icmp_delaytable = {}
tcp_delaytable = {}
dns_delaytable = {}

target_map = {
    "ADDRv4": "ipv4",
    "ADDRv6": "ipv6",
    "COU": "cou",
    "ISP": "isp",
    "LAT": "lat",
    "LNG": "lng",
    "UPDATED_TIME": "time"
}


class TargetSchema(Schema):
    ipv4 = String()
    ipv6 = String()
    protocol = List(String())
    protect = String()
    cou = String()
    isp = String()
    lat = Float()
    lng = Float()
    time = DateTime()


class TestNode(Schema):
    Id = String()
    Name = String()
    Ip = String()
    Lat = Float()
    Lng = Float()
    Loc = String()
    # Port = Integer()


class Delay(Schema):
    Id = String()
    CurrDelay = String()
    # MeanDelay=Integer()
    # MaxDelay=Integer()
    Type = String()


class DelayOut(Schema):
    code = Integer()
    delay_data = List(Nested(Delay()))

from marshmallow import Schema, fields

class ProtectSchema(Schema):
    dnssec_enabled = fields.Boolean(description="是否启用 DNSSEC（DNS 安全扩展）")
    _0x20_encoding = fields.Boolean(description="是否使用 0x20 编码（域名是否随机化大小写）")
    merge_dup = fields.Boolean(description="是否支持合并重复的 DNS 记录")
    max_ns_cnt = fields.Integer(description="查询中允许的最大名称服务器（NS）记录数量")
    max_cname_cnt = fields.Integer(description="查询中允许的最大 CNAME 链深度")
    retry_limit = fields.Integer(description="在失败后重试 DNS 查询的最大次数")
    fetch_limit = fields.Integer(description="在一次查询中可以获取的最大资源记录数")
    timeout = fields.Integer(description="DNS 查询的超时时间，单位是毫秒")
    random_port = fields.Boolean(description="是否使用随机端口进行 DNS 查询")
    random_id = fields.Boolean(description="是否使用随机 ID 进行 DNS 查询")
    version = fields.String(description="DNS 软件版本")
    bailiwick = fields.Boolean(description="是否遵循 Bailiwick 规则")
    max_ttl = fields.Integer(description="最大 TTL 值，单位为秒")
    min_ttl = fields.Integer(description="最小 TTL 值，单位为秒")
    edns_support = fields.Boolean(description="是否支持 EDNS")
    rrl_qps = fields.Integer(description="每秒允许的资源记录锁查询次数")

class TestNode(Schema):
    Id = fields.String()
    Name = fields.String()
    Ip = fields.String()
    Lat = fields.String()
    Lng = fields.Float()
    Loc = fields.Float()
    addrv4 = fields.String()
    addrv6 = fields.Boolean()
    ipv6 = fields.Boolean()
    dnssec = fields.Boolean()
    dot = fields.Boolean()
    doh = fields.Boolean()
    cou = fields.String()
    isp = fields.String()
    lat = fields.Float()
    lng = fields.Float()
    protect = fields.Nested(ProtectSchema)



# 地图统计信息返回结构体
class CouInfo(Schema):
    # 国家名称
    name = String()
    # 不同协议的解析器详细数量说明
    title = String()
    # 总数量
    value = Integer()


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
    query_session = db.session
    # 查询负责该任务的所有状态感知节点简要信息
    node_data = query_session.query(Task.SCAN_AGENT_ID_LIST).filter(Task.task_id == query_data['taskid']).all()

    # 存在数据
    if len(node_data) > 0:
        # 负责该任务目标的状态感知的节点
        nodes_info = json.loads(node_data[0].SCAN_AGENT_ID_LIST)
        # 查询每一个节点的信息
        nodes = query_session.query(Agent).filter(Agent.agent_id.in_(nodes_info.keys())).all()
        for node in nodes:
            node_list.append({
                "Id": node.agent_id,
                "Name": "编号" + str(node.agent_id),
                "Ip": nodes_info[node.agent_id],
                # TODO:根据经纬度调整location的值
                "Loc": "中国",
                "Lat": float(node.lat),
                "Lng": float(node.lng)
            })
        query_session.close()
    else:
        query_session.close()
        return {"code": 500, "nodes": []}

    return {"code": 200, "nodes": node_list}


@bp.get("/delay")
@bp.doc("获取一个目标每个对应探测节点的时延数据", "type参数为{icmp,dns,tcp}中的一个")
@bp.input({
    "target": IP(required=True),
    "taskid": String(required=True),
    "type": String(required=True, validate=OneOf(['icmp', 'dns', 'tcp']))
    }, location="query")
@bp.output(DelayOut)
def get_pernode_delay(query_data):
    query_session = db.session
    # TODO:DoH处理
    # 探测地址
    addr = query_data['target']
    taskid = query_data['taskid']
    scan_type = query_data['type']

    # 响应数据
    ans = []
    # 线程池
    threads = []

    # 检索探测节点信息
    # 查询负责该任务的所有状态感知节点简要信息
    node_data = query_session.query(Task.SCAN_AGENT_ID_LIST).filter(Task.task_id == taskid).all()

    # 存在数据
    if len(node_data) > 0:
        # 负责该任务目标的状态感知的节点ID和IP地址+端口号组成的列表
        nodes_info = json.loads(node_data[0].SCAN_AGENT_ID_LIST)
        # 向每个节点查询时延信息
        for id, ip_port in nodes_info.items():
            mythread = threading.Thread(target=task, args=[ans, addr, {'id': id, 'ip_port': ip_port}, scan_type])
            mythread.start()
            threads.append(mythread)
        for t in threads:
            t.join()
        query_session.close()
    else:
        query_session.close()
        return {"code": 500, "delay_data": []}

    return {"code": 200, 'delay_data': ans}


threadLock = threading.Lock()


def task(ans, addr, agent, scan_type):
    res = 0
    if scan_type == "icmp":
        res = icmp_delay_query(addr, agent['ip_port'])
    if scan_type == "tcp":
        res = tcp_delay_query(addr, agent['ip_port'])
    if scan_type == "dns":
        res = dns_delay_query(addr, agent['ip_port'])
    threadLock.acquire()
    ans.append({
        'Id': agent['id'],
        'CurrDelay': res,
        'Type': scan_type})
    threadLock.release()


def icmp_delay_query(target, addr_port):
    try:
        res = requests.get(url="http://" + addr_port + "/delay/icmp", params={'ip': target}, timeout=5)
        debug("icmp ok:" + addr_port + "-------" + res.text + "-------" + str(res.elapsed.total_seconds()))
        icmp_delaytable[str(addr_port) + str(target)] = res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr_port) + str(target) in icmp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            icmp_delaytable[str(addr_port) + str(target)] = 0
        return icmp_delaytable[str(addr_port) + str(target)]


def tcp_delay_query(target, addr_port):
    try:
        res = requests.get(url="http://" + addr_port + "/delay/tcp", params={'ip': target, 'port': 53}, timeout=5)
        debug("tcp ok:" + addr_port + "-------" + res.text)
        tcp_delaytable[str(addr_port) + str(target)] = res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr_port) + str(target) in tcp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            tcp_delaytable[str(addr_port) + str(target)] = 0
        return tcp_delaytable[str(addr_port) + str(target)]


def dns_delay_query(target, addr_port):
    try:
        res = requests.get(url="http://" + addr_port + "/delay/dns", params={'ip': target}, timeout=5)
        debug("dns ok:" + addr_port + "-------" + res.text)
        dns_delaytable[str(addr_port) + str(target)] = res.text
        return dns_delaytable[str(addr_port) + str(target)]
    except Timeout:
        # 如果存在旧数据
        if str(addr_port) + str(target) in dns_delaytable.keys():
            pass
        # 不存在则设0
        else:
            dns_delaytable[str(addr_port) + str(target)] = 0
        return dns_delaytable[str(addr_port) + str(target)]


# 状态感知——DNS记录测试接口
import dns.nameserver
from apiflask.fields import String
from apiflask.validators import OneOf, ContainsOnly
from dns import resolver

def get_record(query_data):
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
    return ans
@bp.get("/check")
@bp.doc("通过指定的解析器获取指定域名的A/AAAA记录", description="参数说明:</br>" +
                                                                "rev:解析器的IP地址</br>"
                                                                + "domain:查询的目标域名</br>"
                                                                + "qtype:查询的记录类型")
@bp.input({
    'rev': String(required=True),
    'domain': String(required=True),
    'qtype': String(required=True, validate=OneOf(['A', 'AAAA', "CNAME", "NS"]))
}, location='query')
@bp.output({
    "code": Integer(),
    "ans": List(Dict(String(validate=ContainsOnly(["rrset"])), String()))
})
def record(query_data):
   ans = get_record(query_data)
    return {"code": 200, 'ans': ans}


@bp.get("/")
@bp.doc("(表格)目标信息获取接口", "返回目标信息")
@bp.input({
    "protocol": String(load_default=None, validate=OneOf(['IPv6', 'DNSSEC', "DoH", "DoT"])),
    "cou": String(load_default=None),
    "isp": String(load_default=None),
    "per_page": Integer(load_default=10),
    "page": Integer(load_default=1),
    "ip": IP(load_default=None)
}, location='query')
@bp.output({
    "code": Integer(),
    "data": List(Nested(TargetSchema())),
    "total": Integer()
})
def target_info(query_data):
    per_page = query_data["per_page"]
    page = query_data["page"]
    proto = query_data["protocol"]
    cou = query_data["cou"]
    isp = query_data["isp"]
    ip = query_data["ip"]

    # 目标信息列表
    target_list = []
    query = db.session.query(Target)
    # 普通检索，默认所有条件为单选
    if ip is None:
        # 分页查询
        res = query.filter(
            or_(Target.ipv6 == True, proto != 'IPv6'),
            or_(Target.dnssec == True, proto != 'DNSSEC'),
            or_(Target.doh == True, proto != 'DoH'),
            or_(Target.dot == True, proto != 'DoT'),
            or_(Target.cou == cou, cou == None),
            or_(Target.isp == isp, isp == None)).paginate(page=page, per_page=per_page)
        # 查询总数
        res_count = res.total
    else:
        # 查询目标，根据v4、v6地址分类
        res = query.filter(
            or_(Target.addrv6 == ip, ipaddress.ip_address(ip).version != 6),
            or_(Target.addrv4 == ip, ipaddress.ip_address(ip).version != 4)).all()
        # 查询总数
        res_count = len(res)
    # 结果转换
    for r in res:
        target = {
            "ipv4": r.addrv4,
            "ipv6": r.addrv6,
            "cou": r.cou,
            "isp": r.isp,
            "lat": r.lat,
            "lng": r.lng,
            "time": r.updated_time
        }

        # 支持的协议特殊处理
        protocol = []
        # 目标各协议支持情况
        proto_state = {"IPv6": r.ipv6, "DNSSEC": r.dnssec, "DoH": r.doh, "DoT": r.dot}
        for k, v in proto_state.items():
            if bool(v) is True:
                protocol.append(k)
        target["protocol"] = protocol

        # 防护措施特殊处理
        target["protect"] = json.dumps(r.protect)
        target_list.append(target)
    return {"code": 200, "data": target_list, "total": res_count}


@bp.get("/filter")
@bp.doc("目标可筛选信息获取接口")
@bp.output({
    "code": Integer(),
    "proto": List(String()),
    "isp": List(String()),
    "cou": List(String())
})
def filter_info():
    proto = ["IPv6", "DNSSEC", "DoH", "DoT"]

    query_session = db.session
    # 查询所有的isp
    isp_data = query_session.query(distinct(Target.isp)).all()
    # 执行查询
    isp = [i[0] for i in isp_data]

    # 查询所有的国家
    cou_data = query_session.query(distinct(Target.cou)).all()
    # 执行查询
    cou = [i[0] for i in cou_data]

    query_session.close()
    return {"code": 200, "proto": proto, "isp": isp, "cou": cou}


@bp.get("/map")
@bp.doc("地图信息获取接口")
@bp.input({
    "zoom_level": Integer(),
    "min_lat": Float(required=False),
    "max_lat": Float(required=False),
    "min_lng": Float(required=False),
    "max_lng": Float(required=False)
}, location="query")
# @bp.output({ 
#     "code": Integer(),
#     "data": List(Nested(ClusterInfo() if query_data.get("zoom_level") < 10 else TargetInfo())),
#     "total": Integer(),
# })

def map_info(query_data):
    zoom_level = query_data.get("zoom_level")  # 从前端获取缩放级别
    min_lat = query_data.get("min_lat")  # 获取最小纬度
    max_lat = query_data.get("max_lat")  # 获取最大纬度
    min_lng = query_data.get("min_lng")  # 获取最小经度
    max_lng = query_data.get("max_lng")  # 获取最大经度
    if zoom_level <= 10:

        # 查询目标数据
        query = db.session.query(Target.lat, Target.lng).filter(
            and_(
                Target.lat >= min_lat,
                Target.lat <= max_lat,
                Target.lng >= min_lng,
                Target.lng <= max_lng
            )
        )

        # 查询符合条件的数据
        res = query.all()

        # 结果数量
        res_count = len(res)

        # 如果没有结果，返回空数据
        if res_count == 0:
            return {"code": 200, "data": [], "total": 0}

        # 处理数据，提取经纬度信息
        lat_lng = np.array([[float(r.lat), float(r.lng)] for r in res])
        # 聚类操作，当 zoom_level 小于 10 时进行聚类
        num_clusters = max(1, int(res_count / (30000 / zoom_level)))  # 根据缩放级别动态调整聚类数量
        kmeans = MiniBatchKMeans(n_clusters=num_clusters, n_init=5, batch_size=1000)
        kmeans.fit(lat_lng)
        centers = kmeans.cluster_centers_

        # 聚类结果转换
        clustered_data = []
        for i, center in enumerate(centers):
            clustered_data.append({
                "lat": center[0],
                "lng": center[1],
                "count": int(sum(kmeans.labels_ == i))  # 统计每个聚类的节点数量
            })

        return {"code": 200, "data": clustered_data}

    else:
        # 当 zoom_level 大于等于 10 时，返回详细信息
        r = db.session.query(Target).filter(
            and_(
                Target.lat >= min_lat,
                Target.lat <= max_lat,
                Target.lng >= min_lng,
                Target.lng <= max_lng
            )
        )
        target_list = []
        for r_item in r:
            target = {
                "ipv4": r_item.addrv4,
                "ipv6": r_item.addrv6,
                "cou": r_item.cou,
                "isp": r_item.isp,
                "lat": r_item.lat,
                "lng": r_item.lng,
                "time": r_item.updated_time
            }

            protocol = []
            proto_state = {"IPv6": r_item.ipv6, "DNSSEC": r_item.dnssec, "DoH": r_item.doh, "DoT": r_item.dot}
            for k, v in proto_state.items():
                if bool(v):
                    protocol.append(k)
            target["protocol"] = protocol
            target["protect"] = json.dumps(r_item.protect)

            target_list.append(target)

        return {"code": 200, "data": target_list}

    

@bp.get("/gz")
@bp.doc("目标感知")
@bp.input({
    "ip": IP(required=True)
}, location="query")
@bp.output({
    "code": Integer(),
    "dataObject": List(Nested(TargetSchema())),
})
def target_GZ_API(query_data):
    target_GZ(query_data["ip"])
    return {
        'code': 200,
        'MSG': "success"
    }

def target_GZ(IP_addr):
    # 获取
    csgz = db.session.query(Agent).filter_by(agent_type = 'gjst').all()
    csgz = random.choice(csgz)

    url = f"http://{csgz.ipaddr}:{csgz.port}/target_gz/{IP_addr}"
    protect = requests.get(url)
    
    url = f'https://ipinfo.io/{IP_addr}/json?token=2c3db02b7ffce3'
    response = requests.get(url)
    data = response.json()

    # 存数据库
    target = Target(
        addrv4 = IP_addr,
        addrv6 = False,
        ipv6 = (6 == is_ipaddress(IP_addr)),
        dnssec = json.loads(protect.text)['dnssec_enabled'],
        dot = False,
        doh = False,
        cou = data.get('country'),
        isp = data.get('org'),
        lat = float(data.get('loc').split(',')[0]),
        lng = float(data.get('loc').split(',')[1]),
        protect = protect.text,
        doh_domain = None
    )
    if 6 == is_ipaddress(IP_addr):
        target.addrv6 = IP_addr
        target.ipv6 = True
    elif 4== is_ipaddress(IP_addr):
        target.addrv4 = IP_addr

    existing_obj = db.session.query(Target).filter_by(addrv4 = target.addrv4).first()
    if existing_obj:
        db.session.delete(existing_obj)
    db.session.add(target)
    db.session.commit()
    return target