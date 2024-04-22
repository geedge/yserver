# 渗透、目标参数感知脚本
import subprocess
from concurrent.futures import ThreadPoolExecutor

import select
from apiflask import APIBlueprint
from apiflask.fields import String

bp = APIBlueprint('script', __name__, url_prefix='/script')
# 线程池
executor = ThreadPoolExecutor(5)


@bp.post('/')
@bp.doc("渗透任务参数接收接口", "返回任务执行状态")
@bp.input({
    'policy': String(required=True),
    'param': String(required=True)
})
def start_script(query_data):
    # 执行命令
    exe = [query_data['name']]
    # 执行参数
    params = query_data['param'].split()
    if '.py' in query_data['name']:
        exe = ["python"] + exe
    # 通过
    executor.submit(process_script, exe + params)
    return {"code": 200, "msg": "ok"}


def process_script(command):
    # 开始执行命令，不等待其执行完毕
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        # 使用select来监测stdout和stderr是否有数据
        # select函数会阻塞，直到有数据可读
        # 返回值是三个列表，第一个列表是可读的文件对象
        readable, _, _ = select.select([process.stdout, process.stderr], [], [])

        for stream in readable:
            # 读取输出并转换成字符串
            output = stream.readline().decode('utf-8')
            if output:
                # TODO:存储输出到数据库中
                print(output.strip())

        # 检查子进程是否结束
        if process.poll() is not None:
            break

    # 获取子进程的返回值
    rc = process.wait()
