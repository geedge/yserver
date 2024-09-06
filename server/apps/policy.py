# 策略生成与调整，效果评估模块
import random

from exts import db
from model import Policy, TaskPolicy

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
    return policy_list

def copy_task_policy(task):

    last_policy = task.task_policies[-1].Policy

    task_policy = TaskPolicy(
        policy = last_policy.p_id,
        policy_param = last_policy.policy_param,
        for_task = last_policy.for_task
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()

    return task_policy

# ----------------------------------------调整中心----------------------------------------------------

# 初始task_policy创建
def init_task_policy(task):
    policy_list = chiose_policy(task)
    first_policy = random.choice(policy_list)

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
    # TODO 通信
    policy_list = chiose_policy(task)
    first_policy = random.choice(policy_list)

    task_policy = TaskPolicy(
        policy = first_policy.p_id,
        policy_param = first_policy.p_payload,
        for_task = task.task_id
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()
    target2polocy(task_policy)
    adjust_parameters(task_policy)

# -----------------------------------------不可调整参数------------------------------------------------
def target2polocy(task_policy):
    commmand = task_policy.Policy.p_payload
    # 固定 
        # <target>
    commmand.replace("<target>", task_policy.task.target.addrv4)
        # 篡改 
        # <tamper> 目标域名 (DoH DoT)
    commmand.replace("<tamper>", task_policy.task.target_domain)
        # 注入
        # <inject> 目标域名 (DoH DoT)
        # <ns>     要注入的记录 (DoH DoT)
    commmand.replace("<ns>", task_policy.task.target_rr)
    task_policy.policy_param = commmand
    
    db.session.add(task_policy)
    db.session.commit()

# ----------------------------------------可调整参数-----------------------------------------------------

# 生成初始参数
def generate_parameters(task_policy):
    commmand = task_policy.Policy.p_payload
    # 调整
    # DDoS
    # <n> 启动请求发送的进程数(DoT DoH)   包数 (DNSSEC v6)
    if task_policy.Policy.p_proto=="DOH" or task_policy.Policy.p_proto=="DOT":
        commmand.replace("<n>", '4')
    elif task_policy.Policy.p_proto=="DNSSEC" :
        commmand.replace("<n>", '30000')
    elif task_policy.Policy.p_proto=="IPv6":
        commmand.replace("<n>", '10000')
    # <r> 发包速率(DNSSEC)
    if task_policy.Policy.p_proto=="DNSSEC" :
        commmand.replace("<r>", '300')
    # <round> 向CND节点发送的请求次数 (DoT)
    
    # <wait> pending 总时长 (DoT)
    db.session.add(task_policy)
    db.session.commit()

# 生成调整参数

def adjust_parameters(task_policy):
    # 调整
    # DDoS
    # <n> 启动请求发送的进程数(DoT DoH)   包数 (DNSSEC v6)

    # <r> 发包速率(DNSSEC)
    
    # <round> 向CND节点发送的请求次数 (DoT)
    
    # <wait> pending 总时长 (DoT)

    pass
