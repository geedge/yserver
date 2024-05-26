# 策略生成与调整，效果评估模块
import random

from settings import *
from .util import da, is_ipaddress


# 初始策略创建,输入参数为期望策略类型、目标（IP或域名）以及任务编号
def init_task_policy(ptype, target, task):
    ip_version = is_ipaddress(target)
    # 非ip地址，默认为DoH域名
    if ip_version is None:
        # TODO:DoH处理
        res = da.get_data(data_type="target", search={""})
    # IPv4
    elif ip_version == 4:
        res = da.get_data(data_type="target", search={"ADDRv4": target})
    # IPv6
    elif ip_version == 6:
        res = da.get_data(data_type="target", search={"ADDRv6": target})
    else:
        exit(1)

    # 目标支持协议范围
    proto = []
    # 不存在该目标的相关记录
    # TODO:后续对该目标进行探测
    if len(res) == 0:
        proto = ["IPv6", "DOH", "DOT", "DNSSEC"]
    # 存在该目标的记录
    else:
        t = res[0]
        for k in ["IPv6", "DOH", "DOT", "DNSSEC"]:
            if t[k]:
                proto.append(k)

    # 可选策略范围 policy
    # 根据用户期望手段与目标协议寻找初始化策略
    # auto自动包含两类策略
    if ptype == "auto":
        policy = ["ddos", "sjqp"]
    # 否则仅支持用户选定的策略类型
    else:
        policy = [ptype]

    # 策略记录,将上述两个范围列表proto，policy中的值组合进sql语句中
    sql = """
    SELECT P_ID,P_NAME,P_EXE,P_PAYLOAD 
    FROM %s
    WHERE P_TYPE IN (%s) AND P_PROTO IN (%s)
    """ % (MYSQL_TAB_POLICY, "\'" + "\',\'".join(policy) + "\'", "\'" + "\',\'".join(proto) + "\'")
    da.cursor.execute(sql)
    policy_list = da.cursor.fetchall()
    # 随机选择一个作为初始策略
    first_policy = random.choice(policy_list)
    # 策略对应的执行文件路径
    p_exe = first_policy["P_EXE"]
    # 策略对应的初始参数
    p_param = first_policy["P_PAYLOAD"]

    task_policy_info = {"policy": first_policy["P_ID"], "param": p_param, "task": task, "tab": MYSQL_TAB_TASKPOLICY}

    # 记录该任务策略
    task_policy_sql = """
    INSERT INTO %(tab)s
    (POLICY,
    POLICY_PARAM,
    FOR_TASK)
    VALUES('%(policy)s', '%(param)s', '%(task)s')
    """ % task_policy_info

    # 获取任务策略的主键值
    da.cursor.execute(task_policy_sql)
    tp_id = da.conn.insert_id()
    da.conn.commit()

    return tp_id, p_exe, p_param
