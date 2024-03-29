# DNS记录测试接口
import dns.nameserver
from apiflask import APIFlask,APIBlueprint
from apiflask.fields import List,String,Nested
from apiflask.validators import OneOf
from dns import resolver

bp=APIBlueprint("check",__name__,url_prefix="/check")

@bp.route("/")
@bp.doc("通过指定的解析器获取指定域名的A/AAAA记录")
@bp.input({
    'rev':String(required=True),
    'domain':String(required=True),
    'qtype':String(required=True,validate=OneOf(['A','AAAA',"CNAME","NS"]))
    },location='query')
def record(query_data):
    # 特殊协议头
    protols=["https","tls"]
    ans=[]
    # 参数读取
    rev=query_data['rev']
    domain=query_data['domain']
    qtype=query_data['qtype']

    # 解析器配置
    myResolver=resolver.Resolver()
    # 根据rev参数配置解析器
    is_Do53=any(proto if proto in rev else False for proto in protols)
    if not is_Do53:
        # 存在端口指定
        if ":" in rev:
            res=rev.split(":")
            myResolver.nameservers=[dns.nameserver.Do53Nameserver(res[0],port=res[1])]
        else:
            myResolver.nameservers=[rev]
    else:
        #  doh服务
        if "https" in rev:
            myResolver.nameservers=[dns.nameserver.DoHNameserver(url=rev)]
        # dot服务
        if "tls" in rev:
            res=rev.split("//")
            myResolver.nameservers=[dns.nameserver.DoTNameserver(address=res[1])]
    myAnswers = myResolver.resolve(domain, qtype)
    if myAnswers.rrset is not None:
        for r in myAnswers.rrset:
            ans.append({"rrset":str(r)})
    return {'ans':ans}

    



