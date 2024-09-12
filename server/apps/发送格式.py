{
    "clxz": "ddos/sjqp",
    "script":"DoH DDoS",
    "mbgz":{
        "dnssec_enabled": True,          # 是否启用 DNSSEC（DNS 安全扩展）
        "0x20_encoding": False,          # 是否使用 0x20 编码（域名是否随机化大小写）
        "merge_dup": True,               # 是否支持合并重复的 DNS 记录
        "max_ns_cnt": 5,                 # 查询中允许的最大名称服务器（NS）记录数量
        "max_cname_cnt": 10,             # 查询中允许的最大 CNAME 链深度
        "retry_limit": 3,                # 在失败后重试 DNS 查询的最大次数
        "fetch_limit": 100,              # 在一次查询中可以获取的最大资源记录数
        "timeout": 2000,                 # DNS 查询的超时时间，单位是毫秒
        "random_port": True,             # 是否使用随机端口进行 DNS 查询
        "random_id": False,              # 是否使用随机 ID 进行 DNS 查询
        "version": "1.0.0",              # DNS 软件版本
        "bailiwick": True,               # 是否遵循 Bailiwick 规则
        "max_ttl": 3600,                 # 最大 TTL 值，单位为秒
        "min_ttl": 300,                  # 最小 TTL 值，单位为秒
        "edns_support": True,            # 是否支持 EDNS(拓展DNS)
        "rrl_qps": 50                    # 每秒允许的资源记录锁（Rate Limiting）查询次数
    },
    
    "ztgz":{
        "icmp":2,
        "tcp":2,
        "dns":2,
        "record":0.1
    },     
    "para":{
        "n": 4
        }
}

adjust = {
    "mode": "keep/parameter/script",
    "script": None,
    "parameter":{
        "n": 6,
    },
}