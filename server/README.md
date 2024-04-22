# YYserver

## 简介

主控端代码，运行app.py将启动一个flask服务，默认端口为12525。
包含三个分支：
main分支，稳定版本
dev分支，用于根据fake分支完善的接口定义开发实际业务逻辑
fake分支，用于快速定义新的数据接口与前端对接

访问/docs可以看到swagger-api文档

各接口的字段详细定义见apps文件夹下各文件

| 文件           | 接口   |
|--------------|------|
| agentcomm.py | 代理信息 |
| sysinfo.py   | 仪表盘  |
| sysmanage.py | 系统管理 |
| target.py    | 目标感知 |
| task.py      | 任务管理 |

model.py文件包含了一些参数与数据库表字段名或类型之间的映射关系

util.py 提供了访问数据库的工具类和日志输出函数

## 部署过程

1. 首先根据script.sql创建符合要求的数据库表，并在settings.py中配置对应的数据库连接选项
2. 接下来使用pip 根据requirements.txt安装第三方环境依赖

```shell
pip install -r requirements.txt
```

3. 启动主控端服务

```shell
python app.py
```