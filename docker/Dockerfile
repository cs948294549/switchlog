FROM python:3.9-slim

WORKDIR /app

# 东八区：日志时间戳和设备侧对得上才好排查
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/

COPY . .

RUN mkdir -p /app/logs

# syslog 收包端口。UDP，不是 TCP
EXPOSE 5514/udp

# 看主进程在不在。没有 HTTP 接口可探
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
  CMD ps aux | grep -v grep | grep -q "python.*main.py" || exit 1

CMD ["python3", "-u", "main.py"]
