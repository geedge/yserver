# 目标感知
import subprocess
from apiflask import APIBlueprint
from apiflask.fields import String
from flask import json

bp = APIBlueprint('target_gz', __name__, url_prefix='/target_gz')

@bp.get('/<IP>')
@bp.doc("对攻击目标进行目标感知")
def execute_command(IP):
    output = None
    while not output:
        proc = subprocess.Popen(f"./apps/TargetGZ_Client_JSON --target {IP}", 
                                shell=True, 
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, 
                                universal_newlines=True,
                                text=True, 
                                encoding='utf-8')

        output = proc.communicate()[0].strip()
        # 报错的情况
        if "udp" in output:
            output = None

    return output