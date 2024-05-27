# 目标状态感知
# 时延测试接口
import random
import threading

import requests
from apiflask import APIBlueprint, Schema
from apiflask.fields import Integer, String, List, Nested, IP, DateTime, Dict
from apiflask.validators import OneOf
from requests.exceptions import Timeout

from settings import *
from .util import da, fake

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


class Delay(Schema):
    Id = Integer()
    CurrDelay = String()
    # MeanDelay=Integer()
    # MaxDelay=Integer()
    Type = String()


class DelayOut(Schema):
    code = Integer()
    delay_data = List(Nested(Delay()))


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
    num = 10
    for i in range(num):
        city = fake.province()
        geo_info = fake.local_latlng(country_code='CN')
        node_list.append({
            "Id": str(i),
            "Name": "测试节点" + str(i),
            "Ip": fake.ipv4(),
            "Loc": city,
            "Lat": geo_info[0],
            "Lng": geo_info[1],
        })
    return {"code": 200, "nodes": node_list}


@bp.get("/delay")
@bp.doc("获取每个节点的时延数据", "type参数为{icmp,dns,tcp}中的一个")
@bp.input({
    "ip": IP(required=True),
    "taskid": String(required=True),
    "type": String(required=True, validate=OneOf(['icmp', 'dns', 'tcp']))}, location="query")
@bp.output(DelayOut)
# TODO:和实际节点联调测试
def get_pernode_delay(query_data):
    # TODO:DoH处理
    # 探测地址
    addr = query_data['ip']
    taskid = query_data['taskid']
    scan_type = query_data['type']

    # 响应数据
    ans = []
    # 线程池
    threads = []
    # # 检索探测节点信息
    # sql = """
    # SELECT SCAN_AGENT_ID_LIST as node_info
    # FROM %s
    # WHERE TASK_ID='%s'
    # """ % (MYSQL_TAB_TASK, taskid)
    # da.cursor.execute(sql)
    # # 探测节点ID与地址
    # nodes = json.loads(da.cursor.fetchall()[0]["node_info"].replace('"', "\""))
    #
    # for id, ip in nodes.items():
    #     mythread = threading.Thread(target=task, args=[ans, addr, {'id': id, 'ip': ip}, type])
    #     mythread.start()
    #     threads.append(mythread)
    # for t in threads:
    #     t.join()

    # 暂未部署实际代理节点，以假数据返回
    ans = []
    for i in range(10):
        ans.append({"Id": str(i), "Type": scan_type, "CurrDelay": random.randint(1, 1000)})
    return {"code": 200, 'delay_data': ans}


threadLock = threading.Lock()


def task(ans, addr, agent, type):
    res = 0
    if type == "icmp":
        res = icmp_delay_query(addr, agent['ip'])
    if type == "tcp":
        res = tcp_delay_query(addr, agent['ip'])
    if type == "dns":
        res = dns_delay_query(addr, agent['ip'])
    threadLock.acquire()
    ans.append({
        'Id': agent['id'],
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
from apiflask.validators import OneOf, ContainsOnly
from dns import resolver


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
    "data": List(Nested(Target())),
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

    # 普通检索，默认所有条件为单选
    if ip is None:
        # 无协议筛选
        if proto == None:
            res = da.get_data(data_type="target", search={"proto": proto, "cou": cou, "isp": isp},
                              offset=(page - 1) * per_page, limit=per_page)
            res_count = da.count_data(data_type="target", search={"proto": proto, "cou": cou, "isp": isp})
        # 协议筛选，填入筛选的协议
        else:
            res = da.get_data(data_type="target", search={proto: True, "cou": cou, "isp": isp},
                              offset=(page - 1) * per_page, limit=per_page)
            res_count = da.count_data(data_type="target", search={proto: True, "cou": cou, "isp": isp})
    else:
        # 查询目标，根据v4、v6地址分类
        res = da.get_data(data_type="target",
                          search={"ADDRv4": ip} if "." in str(ip) else {"ADDRv6": ip})
        res_count = da.count_data(data_type="target", search={"ADDRv4": ip} if "." in str(ip) else {"ADDRv6": ip})
    # 结果转换
    for r in res:
        target = {}
        # 支持的协议特殊处理
        protocol = []
        for k, v in r.items():
            # debug(k + ":" + str(v))
            if k in ["IPv6", "DNSSEC", "DOH", "DOT"] and bool(v) is True:
                protocol.append(k)
        target["protocol"] = protocol
        # 防护措施特殊处理
        protect = str(r["PROTECT"]).split("|")
        target["protect"] = protect
        # 其他统一处理
        for k in target_map.keys():
            # 原数据的值赋给经过映射之后的键
            target[target_map[k]] = r[k]
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
    # 查询所有的isp
    isp_sql = """SELECT DISTINCT ISP from %s """ % MYSQL_TAB_TARGETDATA
    # 执行查询
    da.conn.ping(reconnect=True)
    da.cursor.execute(isp_sql)
    isp_data = da.cursor.fetchall()
    isp = [i.popitem()[1] for i in isp_data]

    # 查询所有的国家
    cou_sql = """SELECT DISTINCT COU from %s """ % MYSQL_TAB_TARGETDATA
    # 执行查询
    da.conn.ping(reconnect=True)
    da.cursor.execute(cou_sql)
    cou_data = da.cursor.fetchall()
    cou = [i.popitem()[1] for i in cou_data]
    return {"code": 200, "proto": proto, "isp": isp, "cou": cou}


@bp.get("/map")
@bp.doc("地图信息获取接口")
@bp.input({
    "protocol": String(load_default=None, validate=OneOf(['IPv6', 'DNSSEC', "DoH", "DoT"])),
    "cou": String(load_default=None),
    "isp": String(load_default=None),
    "ip": IP(load_default=None)
}, location="query")
@bp.output({
    "code": Integer(),
    "dataObject": Dict(String(load_default="earthAddTitle"), List(Nested(CouInfo()))),
})
def map_info(query_data):
    ip = query_data["ip"]
    proto = query_data["protocol"]
    cou = query_data["cou"]
    isp = query_data["isp"]

    if ip is None:
        cou_list = []
        # 比较和默认参数值不同的参数
        differ = set({"proto": proto, "cou": cou, "isp": isp}.items()).difference(
            {"proto": None, "cou": None, "isp": None}.items())
        if differ == set():
            # 在数据表中进行分组查询,无额外筛选
            sql = """
                SELECT T.COU,sum(T.c) as R,sum(T.dnsec) as DNSEC,sum(T.v6) as IPv6,sum(T.dh) as DoH,sum(T.dt) as DoT 
                FROM
                (SELECT COU,count(*) as c,count(DNSSEC=1 or null) as dnsec,count(IPv6=1 or null) as v6,count(DOH=1 or null) as dh,count(DOT=1 or null) as dt
                FROM %s 
                GROUP BY COU,DNSSEC,IPv6,DOH,DOT) as T GROUP BY T.COU;""" % (MYSQL_TAB_TARGETDATA)
        else:
            l = len(differ)
            # 条件字典
            condition = {}
            for _ in range(l):
                key, val = differ.pop()
                # 协议参数在数据表中对应的字段名
                if key == "proto":
                    condition[{'IPv6': "IPv6", "DNSEC": "DNSSEC", "DoH": "DOH", "DoT": "DOT"}[val]] = str(True)
                else:
                    # 国家和isp属性的键只需调整字母为大写
                    key = key.upper()
                    condition[key] = "\"".join(["", str(val), ""])
            # 在数据表中进行分组查询,无额外筛选
            sql = """
                SELECT T.COU,sum(T.c) as R,sum(T.dnsec) as DNSEC,sum(T.v6) as IPv6,sum(T.dh) as DoH,sum(T.dt) as DoT 
                FROM
                (SELECT COU,count(*) as c,count(DNSSEC=1 or null) as dnsec,count(IPv6=1 or null) as v6,count(DOH=1 or null) as dh,count(DOT=1 or null) as dt
                FROM %s 
                WHERE %s 
                GROUP BY COU,DNSSEC,IPv6,DOH,DOT) as T GROUP BY T.COU;""" % (
                MYSQL_TAB_TARGETDATA, " AND ".join(["=".join(condition.popitem()) for _ in range(l)]))

        # 执行查询
        da.conn.ping(reconnect=True)
        da.cursor.execute(sql)
        data = da.cursor.fetchall()
        for d in data:
            # 单一国家的数据
            cou_data = {
                "name": d['COU'],
                'title': "支持各类协议的解析器数量为：{IPv6：" + str(d['IPv6']) + "，DNSSEC：" + str(
                    d['DNSEC']) + "，DoH：" + str(d['DoH']) + "，DoT：" + str(d['DoT']) + "}",
                "value": d['R']
            }
            cou_list.append(cou_data)

        return {"code": 200, "dataObject": {"earthAddTitle": cou_list}}
        # 查询目标
    else:
        # 查询目标，根据v4、v6地址分类
        res = da.get_data(data_type="target",
                          search={"ADDRv4": ip} if "." in str(ip) else {"ADDRv6": ip})
        # 长度为0，不存在该ip的记录，返回404
        if len(res) == 0:
            return {"code": 404, "dataObject": {"earthAddTitle": []}}
        # 支持协议
        proto = []
        for p in ["IPv6", "DNSSEC", "DOH", "DOT"]:
            if res[0][p]:
                proto.append(p)
        target = [{"name": res[0]["COU"],
                   "title": "该解析器支持：" + '、'.join(proto) + " 协议",
                   "value": 1, }]
        return {"code": 200, "dataObject": {"earthAddTitle": target}}
