# 策略生成与调整，效果评估模块
import random
import ipaddress
from .util import is_ipaddress


from exts import db
from model import Policy, Target, TaskPolicy
from .target import target_GZ

def chiose_policy(task):
    if task.target_domain is not None:
        res = None
        # TODO:DoH处理
        pass
    else:
        ip_version = is_ipaddress(task.target_ip)
        if ip_version == 4 :
            res = db.session.query(Target).filter(Target.addrv4==task.target_ip).first()
        elif ip_version == 6:
            res = db.session.query(Target).filter(Target.addrv6==task.target_ip).first()

    # 目标支持协议范围
    proto = []

    # 不存在该目标的相关记录
    if not res:
        target_GZ(task.target_ip)
        proto = ["IPv6"]

    if res.ipv6:
        proto.append("IPv6")
    if res.doh:
        proto.append("DOH")
    if res.dot:
        proto.append("DOT")
    if res.dnssec:
        proto.append("DNSSEC")

    # 可选策略范围 policy
    # 根据用户期望手段与目标协议寻找初始化策略
    # auto自动包含两类策略，否则仅支持用户选定的策略类型
    policy = ["ddos", "sjqp"] if task.ptype == "auto" else [task.ptype]

    # TODO 随机选择一个作为初始策略(策略选择)
    policy_list = db.session.query(Policy).filter(Policy.p_type.in_(policy), Policy.p_proto.in_(proto)).all()
    return policy_list

# 初始task_policy创建
def init_task_policy(task):
    policy_list = chiose_policy(task)
    first_policy = random.choice(policy_list)
    
    # TODO 编写参数（可能要根据不同的Policy做适配！！！！）
    p_param = task.target_domain

    task_policy = TaskPolicy(
        policy = first_policy.p_id,
        policy_param = p_param,
        for_task = task.task_id
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()

    return task_policy

def copy_task_policy(task):

    last_policy = task.task_policies[-1].Policy
    # TODO 编写参数（可能要根据不同的Policy做适配！！！！）
    p_param = task.target_domain

    task_policy = TaskPolicy(
        policy = last_policy.p_id,
        policy_param = p_param,
        for_task = task.task_id
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()

    return task_policy