# 策略生成与调整，效果评估模块
import random

from .util import is_ipaddress


from exts import db
from model import Policy, Target, TaskPolicy

# 初始策略创建,输入参数为期望策略类型、目标（IP或域名）以及任务编号
def init_task_policy(ptype, target, task):
    ip_version = is_ipaddress(target)
    # 非ip地址，默认为DoH域名
    if ip_version is None:
        # TODO:DoH处理
        pass
    # IPv4
    elif ip_version == 4:
        res = db.session.query(Target).filter(Target.addrv4==target).first()
    # IPv6
    elif ip_version == 6:
        res = db.session.query(Target).filter(Target.addrv6==target).first()
    else:
        exit(1)

    # 目标支持协议范围
    proto = []

    # 不存在该目标的相关记录
    if not res:
        # TODO:后续对该目标进行探测，以下为fake
        proto = ["IPv6", "DOH", "DOT", "DNSSEC"]
    # 存在该目标的记录
    else:
        if res.ipv6:
            proto.append("IPv6")
        elif res.doh:
            proto.append("DOH")
        elif res.dot:
            proto.append("DOT")
        elif res.dnssec:
            proto.append("DNSSEC")

    # 可选策略范围 policy
    # 根据用户期望手段与目标协议寻找初始化策略
    # auto自动包含两类策略，否则仅支持用户选定的策略类型
    policy = ["ddos", "sjqp"] if ptype == "auto" else [ptype]
    
    # 随机选择一个作为初始策略
    policy_list = db.session.query(Policy).filter(Policy.p_type.in_(policy), Policy.p_proto.in_(proto)).all()
    first_policy = random.choice(policy_list)
    # 策略对应的执行文件路径和初始参数
    p_exe = first_policy.p_exe
    p_param = first_policy.p_payload

    task_policy = TaskPolicy(
        policy = first_policy.p_id,
        policy_param = p_param,
        for_task = task
    )

    # 记录该任务策略
    db.session.add(task_policy)
    db.session.commit()

    return task_policy.tp_id, p_exe, p_param
