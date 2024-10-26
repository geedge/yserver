FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

# 使用国内源安装依赖
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

CMD ["python", "app.py", "-p", "12528", "-s", "39.107.180.156:12526", "-t", "ztgz"]
