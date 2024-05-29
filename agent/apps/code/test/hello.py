import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--string', type=str, help="输出到控制台的字符串", required=True)
args = parser.parse_args()
print("hello.py开始执行，执行参数为" + args.string)
for _ in range(10):
    time.sleep(1)
    print("hello  " + str(args.string))
