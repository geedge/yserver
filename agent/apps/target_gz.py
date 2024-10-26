# 目标感知
import ast
import subprocess
from apiflask import APIBlueprint
from apiflask.fields import String
from flask import json

bp = APIBlueprint('target_gz', __name__, url_prefix='/target_gz')
PATH = "./apps/code/12_TargetGZ/target_perception.py"

@bp.get('/<IP>')
@bp.doc("对攻击目标进行目标感知")
def execute_command(IP):
    output = None
    while not output:
        proc = subprocess.Popen(f"python3 {PATH} {IP}", 
                                shell=True, 
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, 
                                universal_newlines=True,
                                text=True, 
                                encoding='utf-8')

        output = proc.communicate()[0].strip()
    try:
        output = ast.literal_eval(output)
        # 替换空字符串为 None
        for key, value in output.items():
            if value == "":
                output[key] = None
        print(output)
        return output, 200
    except:
        return 500