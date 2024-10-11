# 策略生成与调整，效果评估模块
import random

from apiflask import APIBlueprint
import requests

from apps.util import debug
from exts import db, scheduler
from model import Policy, TargetStatus, TaskPolicy, Target
from apiflask.fields import String, Integer, IP, DateTime, List, Nested

bp = APIBlueprint("策略接口集合", __name__, url_prefix="/policy")

@bp.get("/")
@bp.doc("获得初始策略")
@bp.input({
    "ip": String(required=True)
}, location="query")
@bp.output({
    "code": Integer(),
    "dataObject": List(String)
})
def target_GZ_API(query_data):
    ip = query_data["ip"]
    target = db.session.query(Target).filter((Target.addrv4 == ip) | (Target.addrv6 ==ip)).first()
    proto = []

    if target.ipv6:
        proto.append("IPv6")
    if target.doh:
        proto.append("DOH")
    if target.dot:
        proto.append("DOT")
    if target.dnssec:
        proto.append("DNSSEC")

    policy_list = db.session.query(Policy).filter(Policy.p_proto.in_(proto)).all()

    policies = []

    for p in policy_list:
        policies.append(p.p_name)

    return {
        'code': 200,
        'dataObject': policies
    }
# --------------------------策略-----------------------------
def chiose_policy(task):
    target = task.target
    # 目标支持协议范围
    proto = []

    if target.ipv6:
        proto.append("IPv6")
    if target.doh:
        proto.append("DOH")
    if target.dot:
        proto.append("DOT")
    if target.dnssec:
        proto.append("DNSSEC")

    # 可选策略范围 policy
    # 根据用户期望手段与目标协议寻找初始化策略
    # auto自动包含两类策略，否则仅支持用户选定的策略类型
    policy = ["ddos", "sjqp"] if task.ptype == "auto" else [task.ptype]

    policy_list = db.session.query(Policy).filter(Policy.p_type.in_(policy), Policy.p_proto.in_(proto)).all()
    
    # TEST
    # policy_list = db.session.query(Policy).filter(Policy.p_id==1).all()
    return policy_list

def copy_task_policy(task):
    with scheduler.app.app_context():
        db.session.close()

        last_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()

        task_policy = TaskPolicy(
            policy = last_policy.policy,
            policy_param = last_policy.policy_param,
            for_task = last_policy.for_task
        )

        # 记录该任务策略
        db.session.add(task_policy)
        db.session.commit()

        return task_policy

# ----------------------------------------调整中心----------------------------------------------------
p_num = 0
# 初始task_policy创建
def init_task_policy(task):
    policy_list = chiose_policy(task)
    global p_num
    # first_policy = random.choice(policy_list)
    first_policy = policy_list[p_num]
    p_num+=1
    task_policy = TaskPolicy(
        policy = first_policy.p_id,
        policy_param = first_policy.p_payload,
        for_task = task.task_id
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()
    target2polocy(task_policy)
    generate_parameters(task_policy)

    return task_policy


# 自动task_policy调整
def center_process_unit(task):
    with scheduler.app.app_context():
        db.session.close()
        task_policy = db.session.query(TaskPolicy).filter_by(for_task = task.task_id).order_by(TaskPolicy.tp_time.desc()).first()
        status = db.session.query(TargetStatus).filter_by(tp_id=task_policy.tp_id).order_by(TargetStatus.time.desc()).first()
        req = {
            "clxz": task.ptype,
            "script": task_policy.Policy.p_name,
            "mbgz": task.target.protect,
            "ztgz": {
                "icmp": status.icmp,
                "tcp": status.tcp,
                "dns": status.dns,
                "record": status.recorde,
            },
            "para": task_policy.policy_param, 
            "task_id": task.task_id
        }
        url = f"http://localhost:12535/adjustment"
        response = requests.post(url, json = req)
        data = response.json()

        # 随机选择一个 data
        # data = random.choices(data_options, weights = [0.6, 0.4])[0]

        debug(data)
        policy = ""
        p_payload = {}
        db.session.close()
        if data["mode"]== "keep":
            copy_task_policy(task)
            return
        elif data["mode"] == "parameter":
            policy = task_policy.policy
            p_payload = task_policy.Policy.p_payload
        elif data["mode"] == "script":
            policy = db.session.query(Policy).filter_by(p_name = data["script"]).first().p_id
            p_payload = db.session.query(Policy).filter_by(p_name = data["script"]).first().p_payload
        debug("新策略或者新参数！！！！！！！！！！！！！！！")
        reason = {data["reason"]}
        debug("原因：：：", reason)
        debug(policy)
        debug(p_payload)
        task_policy = TaskPolicy(
            policy = policy,
            policy_param = p_payload,
            for_task = task.task_id
        )

        # 记录该任务策略
        db.session.add(task_policy)
        db.session.commit()

        target2polocy(task_policy)
        adjust_parameters(task_policy, data["parameter"])
        # 增加默认
        generate_parameters(task_policy)

# -----------------------------------------不可调整参数------------------------------------------------
def target2polocy(task_policy):
    with scheduler.app.app_context():
        task_policy = db.session.query(TaskPolicy).filter_by(tp_id = task_policy.tp_id).first()
        policy = db.session.query(Policy).filter(Policy.p_id == task_policy.policy).first()
        commmand = policy.p_payload
        # 固定 
            # <target>
        commmand = commmand.replace("<target>", task_policy.task.target.addrv4)
            # 篡改 
            # <tamper> 目标域名 (DoH DoT)
        commmand = commmand.replace("<target_domain>", task_policy.task.target_domain)
            # 注入
            # <inject> 目标域名 (DoH DoT)
            # <ns>     要注入的记录 (DoH DoT)
        commmand = commmand.replace("<record>", task_policy.task.target_rr)
        task_policy.policy_param = commmand
        
        # db.session.add(task_policy)
        db.session.commit()

# ----------------------------------------可调整参数-----------------------------------------------------

# 生成初始参数
def generate_parameters(task_policy):
    with scheduler.app.app_context():
        task_policy = db.session.query(TaskPolicy).filter_by(tp_id = task_policy.tp_id).first()

        commmand = task_policy.policy_param
        # 调整
        # DDoS
        # <n> 启动请求发送的进程数(DoT DoH)   包数 (DNSSEC v6)
        if task_policy.Policy.p_proto=="DOH" or task_policy.Policy.p_proto=="DOT":
            commmand = commmand.replace("<n>", '4')
        elif task_policy.Policy.p_proto=="DNSSEC" :
            commmand = commmand.replace("<n>", '30000')
        elif task_policy.Policy.p_proto=="IPv6":
            commmand = commmand.replace("<n>", '10000')
        # <r> 发包速率(DNSSEC)
        if task_policy.Policy.p_proto=="DNSSEC" :
            commmand = commmand.replace("<r>", '300')
        # <round> 向CND节点发送的请求次数 (DoT)
        
        # <wait> pending 总时长 (DoT)
        task_policy.policy_param = commmand
        # db.session.add(task_policy)
        db.session.commit()

# 生成调整参数

def adjust_parameters(task_policy, param):
    with scheduler.app.app_context():
        task_policy = db.session.query(TaskPolicy).filter_by(tp_id = task_policy.tp_id).first()
        commmand = task_policy.policy_param
        for k, v in param.items():
            commmand = commmand.replace(f"<{k}>", str(v))
        
        task_policy.policy_param = commmand
        db.session.commit()