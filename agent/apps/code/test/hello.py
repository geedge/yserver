import subprocess

proc = subprocess.Popen('/root/yserver/agent/apps/code/test/prober comm.e64.fun 10000 124.221.228.62 198.13.47.39 45.32.24.138',
                                shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, 
                            universal_newlines=True,
                            text=True, 
                            encoding='utf-8')

# for line in proc.stdout:
#     print(line)
while proc.poll() is None:
    
    line = proc.stdout.readline()
    if line:
        # 发送每行日志到服务器
        print(line)

proc.stdout.close()
