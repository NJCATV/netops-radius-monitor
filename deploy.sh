#!/bin/bash
# deploy.sh — 一键部署到远程服务器
# 用法：bash deploy.sh

set -e

REMOTE_HOST="172.31.3.117"
REMOTE_USER="${REMOTE_USER:-njcatv}"
REMOTE_PASS="${REMOTE_PASS:?请通过环境变量 REMOTE_PASS 提供 SSH 密码}"
REMOTE_DIR="/opt/radius_monitor"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== 部署 RADIUS 监控系统到 $REMOTE_HOST ==="

# 1. 检查 sshpass
if ! command -v sshpass &>/dev/null; then
    echo "[错误] 请先安装 sshpass: apt install sshpass / brew install hudochenkov/sshpass/sshpass"
    exit 1
fi

SSH="sshpass -p $REMOTE_PASS ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST"
SCP="sshpass -p $REMOTE_PASS scp -o StrictHostKeyChecking=no -r"

# 2. 创建远程目录
echo "[1/5] 创建远程目录..."
$SSH "mkdir -p $REMOTE_DIR"

# 3. 上传项目文件
echo "[2/5] 上传文件..."
$SCP "$LOCAL_DIR/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

# 4. 远程安装 Docker（如未安装）
echo "[3/5] 检查 Docker..."
$SSH "
    if ! command -v docker &>/dev/null; then
        echo '安装 Docker...'
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
        usermod -aG docker $USER || true
    fi
    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
        echo '安装 Docker Compose...'
        curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
    docker --version
"

# 5. 检查/创建 .env
echo "[4/5] 配置环境变量..."
$SSH "
    cd $REMOTE_DIR
    if [ ! -f .env ]; then
        cp .env.example .env
        # 自动检测镜像口网卡
        IFACE=\$(ip -o link show | awk -F': ' '{print \$2}' | grep -v lo | head -1)
        sed -i \"s/^CAPTURE_IFACE=.*/CAPTURE_IFACE=\$IFACE/\" .env
        echo \"自动选择网卡: \$IFACE\"
    fi
"

# 6. 构建并启动
echo "[5/5] 构建并启动容器..."
$SSH "
    cd $REMOTE_DIR
    docker compose pull mysql 2>/dev/null || true
    docker compose build --no-cache
    docker compose up -d
    echo ''
    echo '=== 容器状态 ==='
    docker compose ps
    echo ''
    echo '=== 等待服务就绪 ==='
    sleep 5
    curl -sf http://localhost:5000/health && echo '✅ Web 服务健康' || echo '⚠️  Web 服务尚未就绪，请等待几秒后再试'
"

echo ""
echo "=== 部署完成 ==="
echo "  📊 报表地址：http://$REMOTE_HOST:5000"
echo "  📦 MySQL：$REMOTE_HOST:3306 (radius/radius123)"
echo "  📋 查看日志：ssh $REMOTE_USER@$REMOTE_HOST 'cd $REMOTE_DIR && docker compose logs -f'"
echo "  🔧 修改网卡：ssh $REMOTE_USER@$REMOTE_HOST 'cd $REMOTE_DIR && nano .env && docker compose restart sniffer'"
