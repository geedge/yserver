# 渗透、目标参数感知脚本
import subprocess
from concurrent.futures import ThreadPoolExecutor

from apiflask import APIBlueprint
from apiflask.fields import String

from .util import debug

bp = APIBlueprint('script', __name__, url_prefix='/script')
# 线程池
executor = ThreadPoolExecutor(5)
BASE_PATH = "./apps/code/"


@bp.post('/')
@bp.doc("渗透任务参数接收接口", "返回任务执行状态")
@bp.input({
    'policy': String(required=True),
    'param': String(required=True)
})
def start_script(json_data):
    # 执行命令
    exe = [BASE_PATH + json_data['policy']]
    # 执行参数
    params = json_data['param'].split()
    if '.py' in json_data['policy']:
        exe = ["python"] + exe
    # 通过
    executor.submit(process_script, exe + params)
    return {"code": 200, "msg": "ok"}


def process_script(command):
    # 开始执行命令，不等待其执行完毕
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        output = process.stdout.readline().rstrip().decode('utf-8')
        if output == '' and process.poll() is not None:
            break
        if output == '':
            continue
        if output:
            debug(output.strip())

    # 获取子进程的返回值
    rc = process.poll()
    return rc
