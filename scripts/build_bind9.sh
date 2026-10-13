#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# ─── BIND9 full ProtocolGuard build ────────────────────────────────
# Mirrors scripts/build_unbound.sh but adapted for BIND9's Meson build.
SOURCE=output/bind9-source
IR=output/bind9-ir
STORE=output/bind9-gllvm-store
mkdir -p "$IR" "$STORE" output/logs output/bind9-build output/bind9-install

# Install runtime + dev dependencies
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
    libuv1-dev liburcu-dev liblmdb-dev libjson-c-dev libnghttp2-dev \
    libmaxminddb-dev libidn2-0-dev libssl-dev libcap-dev libxml2-dev \
    libuv1 liburcu8 liblmdb0 libjson-c5 libnghttp2-14 libmaxminddb0 libidn2-0 \
    dnsutils 2>/dev/null | tail -1
pip3 install -q meson ninja 2>/dev/null

COMMON_FLAGS='-Wno-deprecated-declarations'
ANALYSIS_FLAGS="-g -O0 -Xclang -disable-O0-optnone -fno-discard-value-names $COMMON_FLAGS"

# ─── 1) Clang-14 baseline build ────────────────────────────────────
echo "=== Step 1: Baseline build with clang-14 ==="
BLD=output/bind9-baseline-build
rm -rf "$BLD" output/bind9-install-baseline
mkdir -p "$BLD"
cd "$BLD"
meson setup /workspace/$SOURCE \
    --prefix=/workspace/output/bind9-install-baseline \
    -Dprefix=/workspace/output/bind9-install-baseline \
    -Dbuildtype=debug \
    2>&1 | tee /workspace/output/logs/bind9-baseline-configure.log | tail -5
ninja -j4 2>&1 | tee /workspace/output/logs/bind9-baseline-build.log | tail -5
ninja install 2>&1 | tee /workspace/output/logs/bind9-baseline-install.log | tail -3

# Copy named binary
cp /workspace/output/bind9-install-baseline/sbin/named /workspace/output/bind9-binary-baseline
echo "Baseline named built."

# Generate compile_commands.json from Meson
cp "$BLD/compile_commands.json" /workspace/output/bind9-compile_commands.json 2>/dev/null || {
    # Meson always generates compile_commands.json in the build dir
    echo "WARNING: compile_commands.json not found in $BLD"
    find "$BLD" -name 'compile_commands.json' -exec cp {} /workspace/output/bind9-compile_commands.json \;
}
echo "compile_commands.json saved."

# ─── 2) GLLVM whole-program bitcode build ──────────────────────────
echo "=== Step 2: GLLVM whole-program bitcode build ==="
rm -rf output/bind9-gllvm-build output/bind9-install-gllvm
mkdir -p output/bind9-gllvm-build
cd output/bind9-gllvm-build

export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin
export LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link-14 LLVM_AR_NAME=llvm-ar-14
export WLLVM_BC_STORE=/workspace/$STORE

# Use gclang/gclang++ for GLLVM instrumentation
meson setup /workspace/$SOURCE \
    --prefix=/workspace/output/bind9-install-gllvm \
    -Dprefix=/workspace/output/bind9-install-gllvm \
    -Dbuildtype=debug \
    -Db_asneeded=false \
    2>&1 | tee /workspace/output/logs/bind9-gllvm-configure.log | tail -5

# Replace CC/CXX in the build with gclang/gclang++
# Meson doesn't easily allow changing compiler after setup,
# so we set environment variables and reconfigure
CC=gclang CXX=gclang++ meson setup --reconfigure \
    /workspace/$SOURCE \
    2>&1 | tee -a /workspace/output/logs/bind9-gllvm-configure.log | tail -5

ninja -j4 2>&1 | tee /workspace/output/logs/bind9-gllvm-build.log | tail -5
ninja install 2>&1 | tee /workspace/output/logs/bind9-gllvm-install.log | tail -3

# Extract whole-program bitcode from the named binary
NAMED_GLLVM=/workspace/output/bind9-install-gllvm/sbin/named
if [ -f "$NAMED_GLLVM" ]; then
    get-bc -o /workspace/$IR/bind9.bc "$NAMED_GLLVM" 2>&1 | tail -5 || {
        # Try .libs path or find the binary
        echo "get-bc failed on sbin/named, trying alternate paths..."
        find /workspace/output/bind9-gllvm-build -name 'named' -type f -executable \
            -exec get-bc -o /workspace/$IR/bind9.bc {} \; 2>&1 | tail -5
    }
fi

# Verify bitcode
if [ -f /workspace/$IR/bind9.bc ]; then
    echo "BIND9 bitcode extracted successfully: $(wc -c < /workspace/$IR/bind9.bc) bytes"
else
    echo "ERROR: BIND9 bitcode extraction failed"
    # Fallback: try llvm-link on all .bc files in the store
    echo "Attempting fallback: llvm-link all .bc files from store..."
    find /workspace/$STORE -name '*.bc' -type f > /tmp/bind9_bc_files.txt
    if [ -s /tmp/bind9_bc_files.txt ]; then
        xargs llvm-link-14 -o /workspace/$IR/bind9.bc < /tmp/bind9_bc_files.txt
        echo "Fallback linked $(wc -l < /tmp/bind9_bc_files.txt) .bc files"
    else
        echo "FATAL: No .bc files found in store"
        exit 1
    fi
fi

# SSA transformation
opt-14 -passes='mem2reg,loop-mssa(licm)' /workspace/$IR/bind9.bc -o /workspace/$IR/bind9_ssa.bc
echo "SSA bitcode ready."

# ─── 3) Clang AST metadata ─────────────────────────────────────────
echo "=== Step 3: AST metadata ==="
python3 helper_scripts/compile_database.py \
    /workspace/output/bind9-compile_commands.json output/bind9-ast \
    --plugin build/src/libASTPass.so --target '' --ast-only 2>&1 | tail -5

# ─── 4) SVF-2.9 Andersen indirect-call analysis ────────────────────
echo "=== Step 4: SVF analysis ==="
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
"$SVF_ROOT/Release-build/bin/wpa" -print-fp -ander /workspace/$IR/bind9.bc \
    > /workspace/$IR/fp.txt 2> /workspace/output/logs/bind9-svf-wpa.stderr
python3 helper_scripts/indirect_callgraph.py /workspace/$IR/fp.txt /workspace/$IR/ffp.txt

python3 - <<'PY'
import hashlib, json
from pathlib import Path
ir = Path('output/bind9-ir')
meta = {
    'tool': 'SVF', 'tag': 'SVF-2.9',
    'command': ['wpa', '-print-fp', '-ander', 'output/bind9-ir/bind9.bc'],
    'raw_report': 'output/bind9-ir/fp.txt',
    'parsed_report': 'output/bind9-ir/ffp.txt',
    'raw_report_sha256': hashlib.sha256((ir / 'fp.txt').read_bytes()).hexdigest(),
    'parsed_report_sha256': hashlib.sha256((ir / 'ffp.txt').read_bytes()).hexdigest(),
    'parsed_records': sum(1 for line in (ir / 'ffp.txt').read_text().splitlines() if line.strip()),
}
(ir / 'svf_metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps(meta, indent=2))
PY

# ─── 5) Analyzer pass ──────────────────────────────────────────────
echo "=== Step 5: Analyzer pass ==="
PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE="$IR/ffp.txt" \
PROTOCOLGUARD_OUTPUT_DIR=output/bind9-analysis \
opt-14 -load-pass-plugin build/src/libAnalyzerPass.so \
    -passes=analyzer-pass "$IR/bind9_ssa.bc" -disable-output \
    2>&1 | tee output/logs/bind9-analysis.log | tail -10

echo "=== BUILD COMPLETE ==="
echo "Baseline binary: output/bind9-binary-baseline"
echo "Bitcode:         output/bind9-ir/bind9.bc"
echo "SSA bitcode:     output/bind9-ir/bind9_ssa.bc"
echo "SVF report:      output/bind9-ir/ffp.txt"
echo "Analysis:        output/bind9-analysis/analysis.json"
