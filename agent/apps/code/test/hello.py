import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--string', type=str, help="输出到控制台的字符串", required=True)
args = parser.parse_args()
print("hello.py开始执行，执行参数为" + args.string)
f = open("j.txt", "w+", encoding="utf-8")
i = 0
while(1):
    time.sleep(10)
    print(i)
    i+=1