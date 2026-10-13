#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME 信任边界突破 — Docker 一键启动
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

CONTAINER_NAME="unbound-trust-breach"
IMAGE="protocolguard:llvm14"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME 信任边界突破 — Docker 一键启动                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: 确认镜像
if ! docker images | grep -q "protocolguard"; then
    echo "[1/5] 构建 Docker 镜像..."
    docker build -t "$IMAGE" "$PROJECT_DIR"
else
    echo "[1/5] ✓ 镜像已存在"
fi

# Step 2: 启动容器
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo "[2/5] ✓ 容器已在运行"
elif docker ps -a | grep -q "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" > /dev/null 2>&1
    docker run -d --name "$CONTAINER_NAME" --cap-add=NET_ADMIN \
        -v "$PROJECT_DIR:/workspace" "$IMAGE" sleep infinity
    echo "[2/5] ✓ 容器已重新创建"
else
    docker run -d --name "$CONTAINER_NAME" --cap-add=NET_ADMIN \
        -v "$PROJECT_DIR:/workspace" "$IMAGE" sleep infinity
    echo "[2/5] ✓ 容器已创建"
fi

# Step 3: 安装依赖
echo "[3/5] 安装依赖..."
docker exec "$CONTAINER_NAME" bash -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 iproute2 > /dev/null 2>&1
' 2>/dev/null
echo "      ✓ 依赖安装完成"

# Step 4: 编译 Unbound（如果需要）
echo "[4/5] 检查 Unbound 二进制..."
docker exec "$CONTAINER_NAME" bash -c "
if [ ! -f /workspace/output/unbound-binary-baseline ]; then
    echo '      编译 Unbound...'
    cd /workspace/output/unbound-source
    chmod +x configure install-sh config.guess config.sub missing compile depcomp ltmain.sh 2>/dev/null || true
    ./configure CC=clang-14 CFLAGS='-g -O2 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable' > /dev/null 2>&1
    make -j\$(nproc) > /dev/null 2>&1
    cp unbound /workspace/output/unbound-binary-baseline
    echo '      ✓ 编译完成'
else
    echo '      ✓ Unbound 已编译'
fi
"

# Step 5: 执行 PoC
echo "[5/5] 执行信任边界突破 PoC..."
echo "  ─────────────────────────────────────────────────────────────"
docker exec "$CONTAINER_NAME" bash /workspace/scripts/trust_breach_poc.sh
echo "  ─────────────────────────────────────────────────────────────"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  如需交互式调试:                                             ║"
echo "║  docker exec -it $CONTAINER_NAME bash                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
