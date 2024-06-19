# 渗透、目标参数感知脚本
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading
import uuid
from flask import request, jsonify
from apiflask import APIBlueprint
from apiflask.fields import String
import requests
import yaml

from .util import debug

bp = APIBlueprint('script', __name__, url_prefix='/script')
# 线程池
executor = ThreadPoolExecutor(5)
BASE_PATH = "./apps/code/"
# config
config = {}
with open("./config.yaml", "r") as f:
    config = yaml.safe_load(f)

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
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


# 用于存储命令结果和控制信息的字典
tasks = {}
tasks_lock = threading.Lock()


def execute_command(cmd, job_id, stop_event):
    server_url = config['server']
    try:
        proc = subprocess.Popen(cmd, 
                                shell=True, 
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, 
                                universal_newlines=True,
                                text=True, 
                                encoding='utf-8')
        tasks[job_id]['output'] = ''
        
        while proc.poll() is None:
            if stop_event.is_set():
                proc.terminate()
                tasks[job_id]['output'] += "\nExecution terminated."
                break
            
            line = proc.stdout.readline()
            if line:
                with tasks_lock:
                    tasks[job_id]['output'] += line
                
                # 发送每行日志到服务器
                response = requests.post(f"http://{server_url}/agent/res", json={"id" : config['id'],
                                                           "taskpolicy" : job_id,
                                                           "level" : "INFO",
                                                           "info" : line})
                if response.status_code != 200:
                    print(f"Failed to send log to server for job {job_id}: {response.text}")
        
        proc.stdout.close()
        proc.stderr.close()
        
        if not stop_event.is_set():
            remaining_output = proc.communicate()[0]
            with tasks_lock:
                tasks[job_id]['output'] += remaining_output
            
            # 发送剩余输出到服务器
            if remaining_output:
                response = requests.post(f"http://{server_url}/agent/res", json={"id" : config['id'],
                                                           "taskpolicy" : job_id,
                                                           "level" : "INFO",
                                                           "info" : remaining_output})
                if response.status_code != 200:
                    print(f"Failed to send remaining log to server for job {job_id}: {response.text}")
    
    except subprocess.CalledProcessError as e:
        with tasks_lock:
            tasks[job_id]['output'] = e.output
        response = requests.post(f"http://{server_url}/agent/res", json={"id" : config['id'],
                                                   "taskpolicy" : job_id,
                                                   "level" : "INFO",
                                                   "info" : e.output})
        if response.status_code != 200:
            print(f"Failed to send error log to server for job {job_id}: {response.text}")
    except Exception as e:
        print(e)


@bp.route('/execute', methods=['POST'])
def execute():
    data = request.json
    script_path = BASE_PATH + data.get('policy')

    # 检查脚本文件是否存在
    if not os.path.isfile(script_path):
        return jsonify({'error': f'Script file {script_path} not found'}), 404

    # 根据脚本类型构建命令
    if '.py' in script_path:
        command = f'python {script_path} {data.get('param')}'
    elif '.go' in script_path:
        command = f'go run {script_path} {data.get('param')}'
    else:
        return jsonify({'error': 'Unsupported script type'}), 400

    # 生成一个唯一的job_id
    job_id = data.get('id')
    stop_event = threading.Event()

    with tasks_lock:
        tasks[job_id] = {'output': None, 'stop_event': stop_event}

    # 提交任务到线程池
    executor.submit(execute_command, command, job_id, stop_event)
    return '202'


@bp.route('/results/<job_id>', methods=['GET'])
def get_result(job_id):
    with tasks_lock:
        if job_id not in tasks:
            return jsonify({'error': 'Job ID not found or still running'}), 404
        return jsonify({'job_id': job_id, 'output': tasks[job_id]['output']})


@bp.route('/stop/<job_id>', methods=['POST'])
def stop_job(job_id):
    with tasks_lock:
        if job_id not in tasks:
            return jsonify({'error': 'Job ID not found'}), 404
        tasks[job_id]['stop_event'].set()
        return jsonify({'message': f'Job {job_id} termination initiated'}), 200
