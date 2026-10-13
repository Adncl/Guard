#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning — Docker 一键搭建脚本
#  在 Docker 容器中完整复现 Unbound NS→CNAME 跨域缓存投毒攻击
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

# ── 配置 ──
CONTAINER_NAME="unbound-poc"
WORKDIR="/workspace"
OUTPUT_DIR="$WORKDIR/output/unbound-cache-poison"
UNBOUND_BIN="$WORKDIR/output/unbound-binary-baseline"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning — Docker 搭建脚本                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══════════════════════════════════════════════════════════════
# 第一步：构建 Docker 镜像（如果尚未构建）
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 1] 构建 Docker 镜像..."
if ! docker images | grep -q "protocolguard"; then
    docker build -t protocolguard:llvm14 .
    echo "  ✓ 镜像构建完成"
else
    echo "  ✓ 镜像已存在，跳过"
fi

# ═══════════════════════════════════════════════════════════════
# 第二步：启动容器
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 2] 启动容器..."
# 检查容器是否已运行
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo "  ✓ 容器 $CONTAINER_NAME 已在运行"
elif docker ps -a | grep -q "$CONTAINER_NAME"; then
    docker start "$CONTAINER_NAME"
    echo "  ✓ 容器已重启"
else
    docker run -d --name "$CONTAINER_NAME" \
        --cap-add=NET_ADMIN \
        -v "$(pwd):/workspace" \
        protocolguard:llvm14 \
        sleep infinity
    echo "  ✓ 容器已创建并启动"
fi

# ═══════════════════════════════════════════════════════════════
# 第三步：安装依赖
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 3] 安装依赖..."
docker exec "$CONTAINER_NAME" bash -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 iproute2 > /dev/null 2>&1
echo "  ✓ 依赖安装完成"
'

# ═══════════════════════════════════════════════════════════════
# 第四步：编译 Unbound（如果尚未编译）
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 4] 编译 Unbound..."
docker exec "$CONTAINER_NAME" bash -c "
if [ ! -f '$UNBOUND_BIN' ]; then
    cd /workspace/output/unbound-source
    chmod +x configure install-sh config.guess config.sub missing compile depcomp ltmain.sh 2>/dev/null || true
    ./configure CC=clang-14 CFLAGS='-g -O2 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable' > /dev/null 2>&1
    make -j\$(nproc) > /dev/null 2>&1
    cp unbound '$UNBOUND_BIN'
    echo '  ✓ Unbound 编译完成'
else
    echo '  ✓ Unbound 已编译，跳过'
fi
"

# ═══════════════════════════════════════════════════════════════
# 第五步：配置网络（添加 loopback 地址）
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 5] 配置网络..."
docker exec "$CONTAINER_NAME" bash -c '
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
echo "  ✓ 网络配置完成 (127.0.0.2, 127.0.0.3 已添加到 lo)"
'

# ═══════════════════════════════════════════════════════════════
# 第六步：部署攻击脚本
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 6] 部署攻击脚本..."
docker exec "$CONTAINER_NAME" mkdir -p "$OUTPUT_DIR"
docker cp scripts/unbound_cache_poison_final.sh "$CONTAINER_NAME:$OUTPUT_DIR/attack.sh"
echo "  ✓ 攻击脚本已部署"

# ═══════════════════════════════════════════════════════════════
# 第七步：执行攻击
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  [Step 7] 执行攻击 PoC..."
echo "  ─────────────────────────────────────────────────────────"
docker exec "$CONTAINER_NAME" bash "$OUTPUT_DIR/attack.sh"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  ✓ 攻击 PoC 执行完毕"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  如需交互式调试，进入容器：                                 ║"
echo "║  docker exec -it $CONTAINER_NAME bash                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
