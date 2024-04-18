# 记录参数值和数据库表字段名之间的双向映射
from bidict import bidict

from settings import *

# 参数与数据表映射关系
tabmapping = bidict({
    "agent": MYSQL_TAB_AGENT,
    "task": MYSQL_TAB_TASK,
    "user": MYSQL_TAB_USER,
    "target": MYSQL_TAB_TARGETDATA,
    "syslog": MYSQL_TAB_SYSLOG, })

# 参数与数据表中时间字段的映射关系
timemapping = {
    "agent": "START_TIME",
    "task": "CREATED_TIME",
    "user": "CREATED_TIME",
    "target": "UPDATED_TIME",
}

#
agent_keymapping = bidict({
    "atype": "AGENT_TYPE",
    "status": "STATUS",
    "idle": "IDLE"
})

typemapping = {
    "atype": "str",
    "status": "int",
    "idle": "int"
}
