# ── sniffer 阶段：抓包 + 解析 ────────────────────────────────────────────────
# 使用宿主机的 tcpdump，本镜像只负责解析和入库
FROM python:3.11-slim AS sniffer

# 添加 tcpdump 用户（用于降权，与宿主机对应）
RUN groupadd -g 115 tcpdump && \
    useradd -r -u 115 -g tcpdump tcpdump

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# tcpdump 依赖宿主机自带（--network=host 模式下可访问 /usr/bin/tcpdump）
CMD ["python", "sniffer.py"]


# ── web 阶段：Flask 报表服务 ────────────────────────────────────────────────
FROM python:3.11-slim AS web

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

WORKDIR /app/web
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "app:create_app()"]
