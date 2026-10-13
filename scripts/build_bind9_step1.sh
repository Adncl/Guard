#!/usr/bin/env bash
set -euo pipefail
cd /workspace

SOURCE=output/bind9-source
IR=output/bind9-ir
STORE=output/bind9-gllvm-store
mkdir -p "$IR" "$STORE" output/logs

# Install dependencies
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  libuv1-dev liburcu-dev liblmdb-dev libjson-c-dev libnghttp2-dev \
  libmaxminddb-dev libidn2-0-dev libssl-dev libcap-dev libxml2-dev \
  libuv1 liburcu8 liblmdb0 libjson-c5 libnghttp2-14 libmaxminddb0 libidn2-0 \
  2>/dev/null | tail -1
pip3 install -q meson ninja 2>/dev/null

# ─── Step 1: Baseline build with clang-14 ───────────────────────────
echo '=== Step 1: Baseline build ==='
BLD=output/bind9-baseline-build
rm -rf "$BLD" output/bind9-install-baseline
mkdir -p "$BLD"

cd /workspace/"$BLD"
CC=clang-14 CXX=clang++-14 meson setup /workspace/"$SOURCE" \
  --prefix=/workspace/output/bind9-install-baseline \
  -Dbuildtype=debug 2>&1 | tee /workspace/output/logs/bind9-baseline-configure.log | tail -5

ninja -j4 2>&1 | tee /workspace/output/logs/bind9-baseline-build.log | tail -5
ninja install 2>&1 | tee /workspace/output/logs/bind9-baseline-install.log | tail -3

# Copy named binary
cp /workspace/output/bind9-install-baseline/sbin/named /workspace/output/bind9-binary-baseline
export LD_LIBRARY_PATH=/workspace/output/bind9-install-baseline/lib/x86_64-linux-gnu
/workspace/output/bind9-binary-baseline -V 2>&1 | head -1

# Save compile_commands.json
cp /workspace/"$BLD"/compile_commands.json /workspace/output/bind9-compile_commands.json
echo "compile_commands.json saved: $(wc -l < /workspace/output/bind9-compile_commands.json) lines"
echo '=== Step 1 done ==='
