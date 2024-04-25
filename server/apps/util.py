# 工具包
import ipaddress
import sys

import pymysql
from faker import Faker
from faker.providers import company
from faker.providers import date_time
from loguru import logger
from pymysql.cursors import DictCursor

import apps.model as model
from settings import *

fake = Faker("zh_CN")
fake.add_provider(date_time)
fake.add_provider(company)


# 数据库访问类
class DataHandler:

    # 数据库链接及数据库初始化
    def __init__(self):

        # mysql连接,采用字典游标，返回一系列字典值
        try:
            self.conn = pymysql.connect(cursorclass=DictCursor, host=MYSQL_HOST, user='root',
                                        password=MYSQL_PAWD, port=MYSQL_PORT)
        except Exception as e:
            error(str(e))
            # 数据库连接失败，停止后续操作
            sys.exit(1)
        self.cursor = self.conn.cursor()

        # 初始化sql语句
        # 创建数据库
        dbsql = "CREATE DATABASE IF NOT EXISTS %s" % MYSQL_DATADB

        agentsql = """CREATE TABLE IF NOT EXISTS %s (
            `AGENT_ID` varchar(255) NOT NULL PRIMARY KEY,
            `IPADDR` varchar(255),
            `START_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
            `LAT` varchar(255),
            `LNG` varchar(255),
            `AGENT_TYPE` varchar(255),
            `SYS` varchar(255),
            `PORT` int,
            `CPU_NUM` int,
            `STATUS` bool,
            `MEM` varchar(255),
            `IDLE` bool)ENGINE=innodb DEFAULT CHARSET=utf8; """ % MYSQL_TAB_AGENT

        policysql = """CREATE TABLE IF NOT EXISTS %s(
            `P_ID` varchar(255) NOT NULL PRIMARY KEY,
            `P_EXE` varchar(255),
            `P_TYPE` varchar(255),
            `P_DESC` varchar(255),
            `P_PAYLOAD` varchar(255),
            `P_NAME` varchar(255),
        `P_PROTO` varchar(255))ENGINE=innodb DEFAULT CHARSET=utf8; """ % MYSQL_TAB_POLICY

        syslogsql = """CREATE TABLE IF NOT EXISTS %s(
            `LOG_ID` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `LOG_LEVEL` varchar(255),  
            `LOG_INFO` varchar(255),
            `LOG_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
            `S_IP` varchar(255),
            `USER_ID` varchar(255),
            FOREIGN KEY(`USER_ID`) REFERENCES %s(`USER_ID`)
            )ENGINE=innodb DEFAULT CHARSET=utf8;  """ % (MYSQL_TAB_SYSLOG, MYSQL_TAB_USER)

        targetsql = """CREATE TABLE IF NOT EXISTS %s(
            `TARGET_ID` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
        `ADDRv4` varchar(255),
        `ADDRv6` varchar(255),
        `IPv6` bool,
        `DNSSEC` bool,
        `DOT` bool,
        `DOH` bool,
        `COU` varchar(255),
        `ISP` varchar(255),
        `LAT` varchar(255),
        `LNG` varchar(255),
        `UPDATED_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
        `PROTECT` varchar(255),
        `DOH_DOMAIN` varchar(255))ENGINE=innodb DEFAULT CHARSET=utf8; """ % MYSQL_TAB_TARGETDATA

        tasksql = """CREATE TABLE IF NOT EXISTS %s(
            `TASK_ID` varchar(255) NOT NULL PRIMARY KEY,
        `TASK_NAME` varchar(255),
        `AGENT_ID` varchar(255),
        `CREATED_BY` varchar(255),
        `TARGET_IP` varchar(255),
        `CREATED_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
        `POLICY` int,
        `STATUS` varchar(255),
        `POLICY_DELAY` varchar(255),
        `TASK_DELAY` varchar(255),
        `TARGET_SCAN` varchar(255),
        `TARGET_DOMAIN` varchar(255),
        `TARGET_RTYPE` varchar(255),
        `TARGET_RR` varchar(255),
        FOREIGN KEY(`AGENT_ID`) REFERENCES %s(`AGENT_ID`),
        FOREIGN KEY(`CREATED_BY`) REFERENCES %s(`USER_ID`)
        )ENGINE=innodb DEFAULT CHARSET=utf8; """ % (
            MYSQL_TAB_TASK, MYSQL_TAB_AGENT, MYSQL_TAB_USER)

        tasklogsql = """CREATE TABLE IF NOT EXISTS %s(
            `TLOG_ID` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
        `CREATED_BY_AGENT` varchar(255),
        `CREATED_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
        `TLOG_LEVEL` varchar(255),
        `TLOG_INFO` varchar(255),
        `TLOG_TP` int,
        FOREIGN KEY(`CREATED_BY_AGENT`) REFERENCES %s(`AGENT_ID`),
        FOREIGN KEY(`TLOG_TP`) REFERENCES %s(`TP_ID`)
        )ENGINE=innodb DEFAULT CHARSET=utf8;""" % (MYSQL_TAB_TASK_LOG, MYSQL_TAB_AGENT, MYSQL_TAB_TASKPOLICY)

        taskpolicysql = """CREATE TABLE IF NOT EXISTS %s(
            `TP_ID` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
        `TP_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
        `POLICY` varchar(255),
        `POLICY_PARAM` varchar(255),
        `FOR_TASK` varchar(255),
        FOREIGN KEY(`POLICY`) REFERENCES %s(`P_ID`),
        FOREIGN KEY(`FOR_TASK`) REFERENCES %s(`TASK_ID`)
        ) ENGINE=innodb DEFAULT CHARSET=utf8;""" % (MYSQL_TAB_TASKPOLICY, MYSQL_TAB_POLICY, MYSQL_TAB_TASK)

        usersql = """CREATE TABLE IF NOT EXISTS %s(
            `USER_ID` varchar(255) NOT NULL PRIMARY KEY,
        `USER_NAME` varchar(255),
        `CREATED_BY` varchar(255),
        `CREATED_TIME` datetime DEFAULT CURRENT_TIMESTAMP,
        `USER_PWD_HASH` varchar(255),
        `USER_GROUP` varchar(255)) ENGINE=innodb DEFAULT CHARSET=utf8;""" % MYSQL_TAB_USER

        # 和task_policysql存在双向外键引用的问题，需要额外定义
        fkey = """
        ALTER TABLE %s ADD CONSTRAINT `fk_TASK_TASK_POLICY_1`
        FOREIGN KEY(`POLICY`) REFERENCES %s(`TP_ID`)""" % (
            MYSQL_TAB_TASK, MYSQL_TAB_TASKPOLICY)

        # 执行sql语句
        try:
            # 创建数据库
            self.cursor.execute(dbsql)
            self.conn.commit()
            self.conn.select_db(MYSQL_DATADB)

            # 创建表格
            self.cursor.execute(agentsql)
            self.cursor.execute(usersql)
            self.cursor.execute(syslogsql)
            self.cursor.execute(targetsql)
            self.cursor.execute(tasksql)
            self.cursor.execute(policysql)
            self.cursor.execute(taskpolicysql)
            self.cursor.execute(tasklogsql)
            self.conn.commit()

            # 创建外键
            self.cursor.execute(fkey)
        except Exception as e:
            # 重复外键
            if str(e).find("(1826"):
                pass

    # 获取信息(代理、任务)
    # data_type可选范围参照DataHandler.tabmapping的键
    # 若需要按条件检索，则以将检索维度与检索值以字典形式传入search
    def get_data(self, search: dict = None, data_type="agent", offset=0, limit=10, count=False):
        # 参数映射到表名
        tabname = model.tabmapping[data_type]
        # 比较输入参数和默认值的差异
        if search == None:
            differ = set()
        else:
            differ = set(search.items()).difference(model.default_data[data_type].items())
        # 完全一致
        if len(differ) == 0:
            if not count:
                sql = """SELECT * FROM %s LIMIT %s, %s""" % (tabname, offset, offset + limit)
                self.cursor.execute(sql)
                return self.cursor.fetchall()
            else:
                sql = """SELECT count(*) FROM %s""" % (tabname)
                self.cursor.execute(sql)
                return dict(self.cursor.fetchall()[0]).popitem()[1]
        else:
            l = len(differ)
            # 条件字典
            condition = {}
            for _ in range(l):
                key, val = differ.pop()
                # 参数在数据表中对应的字段名
                tab_key = model.keymapping[data_type][key]
                if model.typemapping[key] == "str":
                    condition[tab_key] = "\"".join(["", str(val), ""])
                else:
                    condition[tab_key] = str(val)
            if not count:
                sql = """SELECT * FROM %s WHERE %s LIMIT %s, %s""" % (
                    tabname, " AND ".join(["=".join(condition.popitem()) for _ in range(l)]), offset, offset + limit)
                print(sql)
                self.cursor.execute(sql)
                return self.cursor.fetchall()
            else:
                sql = """SELECT count(*) FROM %s WHERE %s LIMIT %s, %s""" % (
                    tabname, " AND ".join(["=".join(condition.popitem()) for _ in range(l)]), offset, limit)
                self.cursor.execute(sql)
                return dict(self.cursor.fetchall()[0]).popitem()[1]

    # 统计符合条件的信息数量
    def count_data(self, search: dict = None, data_type="agent"):
        return self.get_data(search=search, data_type=data_type, count=True)

    # 统计一段时间内的信息数量
    def count_data_by_time(self, data_type="agent", time=None, search=None):
        tabname = model.tabmapping[data_type]
        timename = model.timemapping[data_type]
        key, value = search.popitem()
        sql = """SELECT COUNT(*) FROM %s WHERE
         DATE_FORMAT(%s,'%Y-%m-%d')=%s AND %s=%s""" % (tabname, timename, time, key, value)
        self.cursor.execute(sql)
        return dict(self.cursor.fetchall()[0]).popitem()[1]


da = DataHandler()


def debug(message, *args, **kwargs):
    logger.debug(message, *args, **kwargs)


def info(message, *args, **kwargs):
    logger.info(message, *args, **kwargs)


def error(message, *args, **kwargs):
    logger.error(message, *args, **kwargs)


# 判断是否为IP地址，若是返回4(IPv4)或6(IPv6),否则返回None
def is_ipaddress(address: str):
    try:
        ip = ipaddress.ip_address(address)
        return int(ip.version)
    except ValueError:
        return None
