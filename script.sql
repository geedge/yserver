create table if not exists AGENT
(
    AGENT_ID   varchar(255)                       not null
        primary key,
    IPADDR     varchar(255)                       null,
    START_TIME datetime default CURRENT_TIMESTAMP null,
    LAT        varchar(255)                       null,
    LNG        varchar(255)                       null,
    AGENT_TYPE varchar(255)                       null,
    SYS        varchar(255)                       null,
    PORT       int                                null,
    CPU_NUM    int                                null,
    STATUS     tinyint(1)                         null,
    MEM        varchar(255)                       null,
    IDLE       tinyint(1)                         null
)
    charset = utf8mb3;

create table if not exists POLICY
(
    P_ID      varchar(255) not null
        primary key,
    P_EXE     varchar(255) null,
    P_TYPE    varchar(255) null,
    P_DESC    varchar(255) null,
    P_PAYLOAD varchar(255) null,
    P_NAME    varchar(255) null,
    P_PROTO   varchar(255) null
)
    charset = utf8mb3;

create table if not exists TARGETDATA
(
    TARGET_ID    int auto_increment
        primary key,
    ADDRv4       varchar(255)                       not null,
    ADDRv6       varchar(255)                       not null,
    IPv6         tinyint(1)                         null,
    DNSSEC       tinyint(1)                         null,
    DOT          tinyint(1)                         null,
    DOH          tinyint(1)                         null,
    COU          varchar(255)                       null,
    ISP          varchar(255)                       null,
    LAT          varchar(255)                       null,
    LNG          varchar(255)                       null,
    UPDATED_TIME datetime default CURRENT_TIMESTAMP null,
    PROTECT      varchar(255)                       null,
    DOH_DOMAIN   varchar(255)                       null,
    constraint TARGETDATA_pk
        unique (ADDRv4),
    constraint TARGETDATA_pk_2
        unique (ADDRv6)
)
    charset = utf8mb3;

create table if not exists USER
(
    USER_ID       varchar(255)                       not null
        primary key,
    USER_NAME     varchar(255)                       null,
    CREATED_BY    varchar(255)                       null,
    CREATED_TIME  datetime default CURRENT_TIMESTAMP null,
    USER_PWD_HASH varchar(255)                       null,
    USER_GROUP    varchar(255)                       null
)
    charset = utf8mb3;

create table if not exists SYSLOG
(
    LOG_ID    int auto_increment
        primary key,
    LOG_LEVEL varchar(255)                       null,
    LOG_INFO  varchar(255)                       null,
    LOG_TIME  datetime default CURRENT_TIMESTAMP null,
    S_IP      varchar(255)                       null,
    USER_ID   varchar(255)                       null,
    constraint SYSLOG_ibfk_1
        foreign key (USER_ID) references USER (USER_ID)
)
    charset = utf8mb3;

create index USER_ID
    on SYSLOG (USER_ID);

create table if not exists TASK
(
    TASK_ID       varchar(255)                       not null
        primary key,
    TASK_NAME     varchar(255)                       null,
    AGENT_ID      varchar(255)                       null,
    CREATED_BY    varchar(255)                       null,
    TARGET_IP     varchar(255)                       null,
    CREATED_TIME  datetime default CURRENT_TIMESTAMP null,
    POLICY        int                                null,
    STATUS        varchar(255)                       null,
    POLICY_DELAY  varchar(255)                       null,
    TASK_DELAY    varchar(255)                       null,
    TARGET_SCAN   varchar(255)                       null,
    TARGET_DOMAIN varchar(255)                       null,
    TARGET_RTYPE  varchar(255)                       null,
    TARGET_RR     varchar(255)                       null,
    constraint TASK_ibfk_1
        foreign key (AGENT_ID) references AGENT (AGENT_ID),
    constraint TASK_ibfk_2
        foreign key (CREATED_BY) references USER (USER_ID)
)
    charset = utf8mb3;

create index AGENT_ID
    on TASK (AGENT_ID);

create index CREATED_BY
    on TASK (CREATED_BY);

create table if not exists TASK_POLICY
(
    TP_ID        int auto_increment
        primary key,
    TP_TIME      datetime default CURRENT_TIMESTAMP null,
    POLICY       varchar(255)                       null,
    POLICY_PARAM varchar(255)                       null,
    FOR_TASK     varchar(255)                       null,
    constraint TASK_POLICY_ibfk_1
        foreign key (POLICY) references POLICY (P_ID),
    constraint TASK_POLICY_ibfk_2
        foreign key (FOR_TASK) references TASK (TASK_ID)
)
    charset = utf8mb3;

alter table TASK
    add constraint fk_TASK_TASK_POLICY_1
        foreign key (POLICY) references TASK_POLICY (TP_ID);

create table if not exists TASK_LOG
(
    TLOG_ID          int auto_increment
        primary key,
    CREATED_BY_AGENT varchar(255)                       null,
    CREATED_TIME     datetime default CURRENT_TIMESTAMP null,
    TLOG_LEVEL       varchar(255)                       null,
    TLOG_INFO        varchar(255)                       null,
    TLOG_TP          int                                null,
    constraint TASK_LOG_ibfk_1
        foreign key (CREATED_BY_AGENT) references AGENT (AGENT_ID),
    constraint TASK_LOG_ibfk_2
        foreign key (TLOG_TP) references TASK_POLICY (TP_ID)
)
    charset = utf8mb3;

create index CREATED_BY_AGENT
    on TASK_LOG (CREATED_BY_AGENT);

create index TLOG_TP
    on TASK_LOG (TLOG_TP);

create index FOR_TASK
    on TASK_POLICY (FOR_TASK);

create index POLICY
    on TASK_POLICY (POLICY);


