# 使用Python 3.9作为基础镜像
FROM python:3.9-slim

# 设置代理（构建时生效）
ARG HTTP_PROXY=http://192.168.80.1:1082
ARG HTTPS_PROXY=http://192.168.80.1:1082
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY

# 设置工作目录
WORKDIR /app

# 安装nodejs和npm（通过代理）
RUN apt-get update && \
    apt-get install -y nodejs npm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY . /app/

# 安装Python依赖（通过代理）
RUN pip install --no-cache-dir -r requirements.txt

# 清除代理（避免运行时继承）
ENV http_proxy=
ENV https_proxy=

# 设置环境变量
ENV PYTHONUNBUFFERED=1

# 启动命令
CMD ["python", "XianyuAutoAsync.py"]
# docker build -t xianyuapp .
# docker run -it xianyuapp bash