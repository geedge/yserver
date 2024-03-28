# 时延测试接口
import random
import threading

import requests
from apiflask.validators import OneOf
from apiflask import APIFlask,APIBlueprint,Schema
from apiflask.fields import Integer,String,List,Nested,IP,Dict
from flask import request
import pandas as pd
from requests.exceptions import Timeout
import numpy as np

bp=APIBlueprint("delay",__name__,url_prefix="/delay")

icmp_delaytable={}
tcp_delaytable={}
dns_delaytable={}

class TestNode(Schema):
    Id = Integer()
    Name=String()
    Ip=String()
    Loc=String()
    Port=Integer()

class Delay(Schema):
    Id=Integer()
    CurrDelay=String()
    # MeanDelay=Integer()
    # MaxDelay=Integer()
    Type=String()
class DelayOut(Schema):
    delay_data=List(Nested(Delay))

# 时延数据列表初始化
# icmpdelay_state={}
# tcpdelay_state={}
# dnsdelay_state={}
# df=pd.read_csv("./server.csv",encoding="utf-8")
# for index,row in df.iterrows():
#     icmpdelay_state[row['id']]={}
#     tcpdelay_state[row['id']]={}
#     dnsdelay_state[row['id']]={}


@bp.get("/<string:type>")
@bp.doc("获取每个节点的时延数据","type参数为{icmp,dns,tcp}中的一个")
@bp.input({"ip":IP(required=False)},location="query")
@bp.output(DelayOut)
def get_pernode_delay(query_data,type):
    addr=""
    if 'ip' in query_data.keys():
        addr=query_data['ip']
    ans = []
    threads=[]
    df = pd.read_csv("./server.csv", encoding="utf-8")
    for index, row in df.iterrows():
        mythread=threading.Thread(target=task,args=[ans,addr,row,type])
        mythread.start()
        threads.append(mythread)
    for t in threads:
        t.join()
    # if type=="icmp":
    #     df=pd.read_csv("./server.csv",encoding="utf-8")
    #     for index,row in df.iterrows():
    #         ans.append({
    #             'Id':row['id'],
    #             'CurrDelay':icmp_delay_query(addr,row['ip']),
    #             'Type':type})
    # if type=="tcp":
    #     df=pd.read_csv("./server.csv",encoding="utf-8")
    #     for index,row in df.iterrows():
    #         ans.append({
    #             'Id':row['id'],
    #             'CurrDelay':tcp_delay_query(addr,row['ip']),
    #             'Type':type})
    # if type=="dns":
    #     df=pd.read_csv("./server.csv",encoding="utf-8")
    #     for index,row in df.iterrows():
    #         ans.append({
    #             'Id':row['id'],
    #             'CurrDelay':dns_delay_query(addr,row['ip']),
    #             'Type':type})
    return {'delay_data':ans}

threadLock = threading.Lock()
def task(ans,addr,row,type):
    if type=="icmp":
        res=icmp_delay_query(addr,row['ip'])
        threadLock.acquire()
        ans.append({
            'Id':row['id'],
            'CurrDelay':res,
            'Type':type})
        threadLock.release()
        return
    if type=="tcp":
        res=tcp_delay_query(addr, row['ip'])
        threadLock.acquire()
        ans.append({
            'Id':row['id'],
            'CurrDelay':res,
            'Type':type})
        threadLock.release()
        return
    if type=="dns":
        res=dns_delay_query(addr, row['ip'])
        threadLock.acquire()
        ans.append({
            'Id':row['id'],
            'CurrDelay':res,
            'Type':type})
        threadLock.release()

def icmp_delay_query(target,addr):
    try:
        res=requests.get(url="http://"+addr+":2525/script/icmpdelay",params={'ip':target},timeout=5)
        print("icmp ok:" + addr + "-------" + res.text+"-------"+str(res.elapsed.total_seconds()))
        icmp_delaytable[str(addr)+str(target)]=res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr)+str(target) in icmp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            icmp_delaytable[str(addr)+str(target)]=0
        return icmp_delaytable[str(addr)+str(target)]



def tcp_delay_query(target,addr):
    try:
        res = requests.get(url="http://" + addr + ":2525/script/tcpdelay", params={'ip': target, 'port': 53}, timeout=5)
        print("tcp ok:" + addr + "-------" + res.text)
        tcp_delaytable[str(addr)+str(target)] = res.text
        return res.text
    except Timeout:
        # 如果存在旧数据
        if str(addr) + str(target) in tcp_delaytable.keys():
            pass
        # 不存在则设0
        else:
            tcp_delaytable[str(addr)+str(target)] = 0
        return tcp_delaytable[str(addr)+str(target)]



def dns_delay_query(target,addr):
    try:
        res = requests.get(url="http://" + addr + ":2525/script/dnsdelay", params={'ip': target},timeout=5)
        print("dns ok:" + addr + "-------" + res.text)
        dns_delaytable[str(addr)+str(target)] = res.text
        return dns_delaytable[str(addr)+str(target)]
    except Timeout:
        # 如果存在旧数据
        if str(addr) + str(target) in dns_delaytable.keys():
            pass
        # 不存在则设0
        else:
            dns_delaytable[str(addr)+str(target)] = 0
        return dns_delaytable[str(addr)+str(target)]



