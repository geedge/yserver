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
    target_ip = db.Column(db.String(255))
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


class TaskLog(db.Model):
    __tablename__ = MYSQL_TAB_TASK_LOG
    tlog_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    created_by_agent = db.Column(db.String(255), db.ForeignKey(f'{MYSQL_TAB_AGENT}.agent_id'))
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

    tasks = db.relationship('Task', backref='agent')
    task_logs = db.relationship('TaskLog', backref='agent')

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
    ipv6 = db.Column(db.Boolean)
    dnssec = db.Column(db.Boolean)
    dot = db.Column(db.Boolean)
    doh = db.Column(db.Boolean)
    cou = db.Column(db.String(255))
    isp = db.Column(db.String(255))
    lat = db.Column(db.String(255))
    lng = db.Column(db.String(255))
    updated_time = db.Column(db.DateTime, server_default=db.func.now())
    protect = db.Column(db.String(255))
    doh_domain = db.Column(db.String(255))


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
