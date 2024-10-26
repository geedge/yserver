from exts import db
from settings import *
import json
import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = MYSQL_TAB_USER
    user_id = db.Column(db.String(255), primary_key=True, nullable=False, )
    user_name = db.Column(db.String(255))
    created_by = db.Column(db.String(255))
    created_time = db.Column(db.TIMESTAMP, server_default=db.func.now())
    user_pwd_hash = db.Column(db.String(255))
    user_group = db.Column(db.String(255))

    syslogs = db.relationship('Syslog', backref='user')
    tasks = db.relationship('Task', backref='user')
    
    def get_id(self):
        return (self.user_id)

    def set_password(self, password):
        self.user_pwd_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.user_pwd_hash, password)


class Task(db.Model):
    __tablename__ = MYSQL_TAB_TASK
    task_id = db.Column(db.String(255), primary_key=True, nullable=False)
    task_name = db.Column(db.String(255))
    agent_id = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_AGENT}.agent_id'))
    created_by = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_USER}.user_id'))
    # target_ip = db.Column(db.String(255))
    target_id = db.Column(db.Integer, db.ForeignKey(f'{MYSQL_TAB_TARGETDATA}.target_id'))
    created_time = db.Column(db.DateTime, server_default=db.func.now())
    ptype = db.Column(db.String(255))
    status = db.Column(db.String(255))
    policy_delay = db.Column(db.String(255))
    task_delay = db.Column(db.String(255))
    target_scan = db.Column(db.String(255))
    target_domain = db.Column(db.String(255))
    target_rtype = db.Column(db.String(255))
    target_rr = db.Column(db.String(255))
    SCAN_AGENT_ID_LIST = db.Column(db.JSON)

    task_policies = db.relationship('TaskPolicy', backref='task', cascade='all, delete-orphan')


class TaskPolicy(db.Model):
    __tablename__ = MYSQL_TAB_TASKPOLICY
    tp_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    tp_time = db.Column(db.DateTime, server_default=db.func.now())
    policy = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_POLICY}.p_id'))
    policy_param = db.Column(db.String(255))
    for_task = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_TASK}.task_id'))

    task_logs = db.relationship('TaskLog', backref='task_policy', cascade='all, delete-orphan')
    target_status = db.relationship('TargetStatus', backref='task_policy', cascade='all, delete-orphan')

class TargetStatus(db.Model):
    __tablename__ = MYSQL_TAB_TARGET_STATUS
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    time = db.Column(db.DateTime, server_default=db.func.now())
    tp_id = db.Column(db.Integer, db.ForeignKey(f'{MYSQL_TAB_TASKPOLICY}.tp_id'))
    icmp = db.Column(db.Float)
    tcp = db.Column(db.Float)
    dns = db.Column(db.Float)
    recorde = db.Column(db.String(255))

class TaskLog(db.Model):
    __tablename__ = MYSQL_TAB_TASK_LOG
    tlog_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    # created_by_agent = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_AGENT}.agent_id'))
    created_time = db.Column(db.DateTime, server_default=db.func.now())
    tlog_level = db.Column(db.String(255))
    tlog_info = db.Column(db.Text)
    tlog_tp = db.Column(db.Integer, db.ForeignKey(f'{MYSQL_TAB_TASKPOLICY}.tp_id'))


class Agent(db.Model):
    __tablename__ = MYSQL_TAB_AGENT
    agent_id = db.Column(db.String(255), primary_key=True, nullable=False)
    ipaddr = db.Column(db.String(255))
    start_time = db.Column(db.DateTime, server_default=db.func.now())
    lat = db.Column(db.String(255))
    lng = db.Column(db.String(255))
    agent_type = db.Column(db.String(255))
    sys = db.Column(db.String(255))
    port = db.Column(db.Integer)
    cpu_num = db.Column(db.Integer)
    status = db.Column(db.Boolean)
    mem = db.Column(db.String(255))
    idle = db.Column(db.Boolean)
    con = db.Column(db.String(255))

    tasks = db.relationship('Task', backref='agent')
    # task_logs = db.relationship('TaskLog', backref='agent')

class Policy(db.Model):
    __tablename__ = MYSQL_TAB_POLICY
    p_id = db.Column(db.String(255), primary_key=True, nullable=False)
    p_exe = db.Column(db.String(255))
    p_type = db.Column(db.String(255))
    p_desc = db.Column(db.String(255))
    p_payload = db.Column(db.String(255))
    p_name = db.Column(db.String(255))
    p_proto = db.Column(db.String(255))

    task_policies = db.relationship('TaskPolicy', backref='Policy')
    

class Syslog(db.Model):
    __tablename__ = MYSQL_TAB_SYSLOG
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    log_level = db.Column(db.String(255))
    log_info = db.Column(db.String(255))
    log_time = db.Column(db.DateTime, server_default=db.func.now())
    s_ip = db.Column(db.String(255))
    user_id = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_USER}.user_id'))


class Target(db.Model):
    __tablename__ = MYSQL_TAB_TARGETDATA
    target_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    addrv4 = db.Column(db.String(255))
    addrv6 = db.Column(db.String(255))
    do53 = db.Column(db.Boolean)
    ipv6 = db.Column(db.Boolean)
    dnssec = db.Column(db.Boolean)
    dot = db.Column(db.Boolean)
    doh = db.Column(db.Boolean)
    cou = db.Column(db.String(255))
    isp = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    updated_time = db.Column(db.DateTime, server_default=db.func.now())
    protect = db.Column(db.JSON, default = {
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
    })
    doh_domain = db.Column(db.String(255))

    tasks = db.relationship('Task', backref='target')


class Target2(db.Model):
    __tablename__ = 'PROFILE'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    IP = db.Column(db.String(255), nullable=True, index=True)
    IPv6 = db.Column(db.String(255), nullable=True, index=True)
    last_probe_time = db.Column(db.Integer, nullable=True)
    previous_probe_time = db.Column(db.Integer, nullable=True)
    port = db.Column(db.String(255), nullable=True)
    transport_protocol = db.Column(db.String(255), nullable=True)
    Do53 = db.Column(db.Integer, nullable=True)
    DoH = db.Column(db.Integer, nullable=True)
    DoT = db.Column(db.Integer, nullable=True)
    ASN = db.Column(db.Integer, nullable=True)
    country = db.Column(db.String(255), nullable=True)
    province = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(255), nullable=True)
    ISP = db.Column(db.String(255), nullable=True)
    owner = db.Column(db.String(255), nullable=True)
    lngwgs = db.Column(db.Double, nullable=True)
    latwgs = db.Column(db.Double, nullable=True)
    software_info = db.Column(db.String(255), nullable=True)
    web_component = db.Column(db.String(255), nullable=True)
    os_type = db.Column(db.String(255), nullable=True)
    tls_jarm_fingerprint = db.Column(db.String(255), nullable=True)
    certificate_serial = db.Column(db.String(255), nullable=True)
    certificate_issuer = db.Column(db.String(255), nullable=True)
    certificate_validity = db.Column(db.String(255), nullable=True)
    http_max_version = db.Column(db.String(255), nullable=True)
    service_path = db.Column(db.String(255), nullable=True)
    request_method = db.Column(db.String(255), nullable=True)
    http_status_code = db.Column(db.String(255), nullable=True)
    http_version = db.Column(db.String(255), nullable=True)
    http_headers = db.Column(db.Text, nullable=True)
    nsec3_support = db.Column(db.Integer, nullable=True)
    encryption_algorithms = db.Column(db.String(255), nullable=True)
    downgrade_attack = db.Column(db.Integer, nullable=True)
    dns_response_packet = db.Column(db.String(255), nullable=True)
    edns = db.Column(db.Integer, nullable=True)
    merge_dup = db.Column(db.Integer, nullable=True)
    dnssec = db.Column(db.Integer, nullable=True)
    random_id = db.Column(db.Integer, nullable=True)
    random_port = db.Column(db.Integer, nullable=True)
    version = db.Column(db.String(255), nullable=True)
    max_ttl = db.Column(db.Integer, nullable=True)
    min_ttl = db.Column(db.Integer, nullable=True)
    retry_limit = db.Column(db.Integer, nullable=True)
    timeout = db.Column(db.Integer, nullable=True)
    fetch_limit = db.Column(db.Integer, nullable=True)
    certificate_cn = db.Column(db.Text, nullable=True)
    certificate_san = db.Column(db.Text, nullable=True)
    components = db.Column(db.String(255), nullable=True)
    cache = db.Column(db.String(255), nullable=True)
    vul = db.Column(db.Text, nullable=True)
    max_ns_cnt = db.Column(db.Integer, autoincrement=False, nullable=True)
    bailiwick = db.Column(db.Integer, autoincrement=False, nullable=True)
    any_response = db.Column(db.Integer, autoincrement=False, nullable=True)
    max_cname_cnt = db.Column(db.Integer, autoincrement=False, nullable=True)
    rrl = db.Column(db.Integer, autoincrement=False, nullable=True)
    proto0x20 = db.Column(db.Integer, autoincrement=False, nullable=True)


# 对单个模型操作
def model_to_dict(model, fields=None, exchange_fields=None):
    """
    将Flask SQLAlchemy的模型对象转换为字典类型
    :param: model : 模型对象
    :param: fields : 需要获取的字段列表，默认为 None，获取全部字段
    :param: exchange_fields : 需要替换名字的字段，{'数据库字段':'前端展示字段'}，有些数据库字段名在展示时需要修改成前端需要的名字
    :return: 返回字典类型
    """
    # 传递空值时
    if not model:
        return {}
    if fields is None:
        # 获取所有列名
        columns = [column.name for column in model.__table__.columns]
        # 排除掉relationships 设置的反向查询字段
        relations = getattr(model.__class__, '__mapper__').relationships
        exclude_cols = [rel.key for rel in relations]
        # print(exclude_cols,'要剔除的反向查询字段')
        # 拿到所有列名-排除的列名
        cols = set(columns) - set(exclude_cols)
        fields = list(cols)

    obj_dict = {}
    for field in fields:
        if field not in model.__dict__:
            continue

        value = model.__dict__[field]
        # 1、对时间字段进行操作
        if isinstance(value, datetime.datetime):
            # 字段类型是datetime的，格式化
            value = value.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(value, datetime.date):
            # 字段类型是date的，格式化
            value = value.strftime('%Y-%m-%d')
        # 2、将所有可以进行反序列化的进行反序列化(将json字符串转成python结构数据类型)
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception as _:
                pass
        #3、替换展示的字段
        if type(exchange_fields) == dict:
            for db_field, show_field in exchange_fields.items():
                #db_field 是数据库字段，show_field是展示字段名
                if field == db_field:
                    field = show_field

        obj_dict[field] = value

    return obj_dict

#对数据集操作
def model_to_dict_list(queryset, fields=None, exchange_fields=None):
    #1、空对象操作
    if not queryset:
        return []
    #2、数据类型控制
    first = queryset[0]
    #3、循环操作
    ret = []
    for obj in queryset:
        dic = model_to_dict(obj, fields=fields, exchange_fields=exchange_fields)
        ret.append(dic)
    return ret
