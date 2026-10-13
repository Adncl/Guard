#!/usr/bin/env bash
set -euo pipefail
cd /workspace

SOURCE=output/bind9-source
IR=output/bind9-ir
STORE=output/bind9-gllvm-store
mkdir -p "$IR" "$STORE" output/logs

apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  libuv1-dev liburcu-dev liblmdb-dev libjson-c-dev libnghttp2-dev \
  libmaxminddb-dev libidn2-0-dev libssl-dev libcap-dev libxml2-dev \
  2>/dev/null | tail -1
pip3 install -q meson ninja 2>/dev/null

# ─── Step 2: GLLVM whole-program bitcode build ──────────────────────
echo '=== Step 2: GLLVM build ==='
export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin
export LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link LLVM_AR_NAME=llvm-ar
export WLLVM_BC_STORE=/workspace/"$STORE"

GLLVM_BLD=output/bind9-gllvm-build
rm -rf "$GLLVM_BLD" output/bind9-install-gllvm
mkdir -p "$GLLVM_BLD"

cd /workspace/"$GLLVM_BLD"

# Meson needs CC/CXX env vars before setup
CC=gclang CXX=gclang++ meson setup /workspace/"$SOURCE" \
  --prefix=/workspace/output/bind9-install-gllvm \
  -Dbuildtype=debug \
  -Db_asneeded=false \
  2>&1 | tee /workspace/output/logs/bind9-gllvm-configure.log | tail -5

# Build with GLLVM-instrumented compilers
ninja -j4 2>&1 | tee /workspace/output/logs/bind9-gllvm-build.log | tail -5
ninja install 2>&1 | tee /workspace/output/logs/bind9-gllvm-install.log | tail -3

# Extract whole-program bitcode from named
echo '=== Extracting bitcode ==='
NAMED_GLLVM=/workspace/output/bind9-install-gllvm/sbin/named
if [ -f "$NAMED_GLLVM" ]; then
    get-bc -o /workspace/"$IR"/bind9.bc "$NAMED_GLLVM" 2>&1 || {
        echo "get-bc failed on sbin/named, trying build dir..."
        find /workspace/"$GLLVM_BLD" -name 'named' -type f -executable | head -1 | \
          xargs -I{} get-bc -o /workspace/"$IR"/bind9.bc {} 2>&1
    }
fi

# Verify bitcode
if [ -f /workspace/"$IR"/bind9.bc ]; then
    echo "BIND9 bitcode extracted: $(wc -c < /workspace/$IR/bind9.bc) bytes"
else
    echo "Primary extraction failed. Trying fallback: llvm-link all .bc from store..."
    find /workspace/"$STORE" -name '*.bc' -type f > /tmp/bind9_bc_files.txt
    COUNT=$(wc -l < /tmp/bind9_bc_files.txt)
    echo "Found $COUNT .bc files in store"
    if [ "$COUNT" -gt 0 ]; then
        xargs llvm-link-14 -o /workspace/"$IR"/bind9.bc < /tmp/bind9_bc_files.txt
        echo "Fallback linked $COUNT .bc files: $(wc -c < /workspace/$IR/bind9.bc) bytes"
    else
        echo "FATAL: No .bc files found in store!"
        exit 1
    fi
fi

# SSA transformation
echo '=== SSA transformation ==='
opt-14 -passes='mem2reg,loop-mssa(licm)' /workspace/"$IR"/bind9.bc -o /workspace/"$IR"/bind9_ssa.bc
echo "SSA bitcode ready: $(wc -c < /workspace/$IR/bind9_ssa.bc) bytes"
echo '=== Step 2 done ==='
