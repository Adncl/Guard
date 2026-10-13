#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Paper case: Mosquitto commit 849e0f, MQTT 5.0. Keep the runnable Clang
# build separate from the GLLVM build consumed by SVF.
SOURCE=output/mosquitto-source
BASELINE=output/mosquitto-build
ANALYSIS=output/mosquitto-gllvm-build
IR=output/mosquitto-ir
STORE=output/mosquitto-gllvm-store
COMMON_FLAGS='-Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable'
ANALYSIS_FLAGS='-g -Xclang -disable-O0-optnone -fno-discard-value-names -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable'

test -f "$SOURCE/CMakeLists.txt"
rm -rf "$BASELINE" "$ANALYSIS" "$IR" "$STORE" output/mosquitto-ast
mkdir -p "$IR" "$STORE"

cmake -S "$SOURCE" -B "$BASELINE" -G Ninja \
  -DCMAKE_C_COMPILER=clang-14 -DCMAKE_CXX_COMPILER=clang++-14 \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_FLAGS="$COMMON_FLAGS" -DCMAKE_CXX_FLAGS="$COMMON_FLAGS" \
  -DWITH_CLIENTS=OFF -DWITH_APPS=OFF -DWITH_PLUGINS=OFF \
  -DWITH_CJSON=OFF -DDOCUMENTATION=OFF -DWITH_LIB_CPP=OFF \
  -DWITH_BUNDLED_DEPS=ON -DWITH_TLS=ON
cmake --build "$BASELINE" -j 2

export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin
export LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link LLVM_AR_NAME=llvm-ar
export WLLVM_BC_STORE=/workspace/$STORE
cmake -S "$SOURCE" -B "$ANALYSIS" -G Ninja \
  -DCMAKE_C_COMPILER=gclang -DCMAKE_CXX_COMPILER=gclang++ \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_FLAGS="$ANALYSIS_FLAGS" -DCMAKE_CXX_FLAGS="$ANALYSIS_FLAGS" \
  -DWITH_CLIENTS=OFF -DWITH_APPS=OFF -DWITH_PLUGINS=OFF \
  -DWITH_CJSON=OFF -DDOCUMENTATION=OFF -DWITH_LIB_CPP=OFF \
  -DWITH_BUNDLED_DEPS=ON -DWITH_TLS=ON
cmake --build "$ANALYSIS" -j 2
get-bc -o "$IR/mosquitto.bc" "$ANALYSIS/src/mosquitto"
opt-14 -passes='mem2reg,loop-mssa(licm)' "$IR/mosquitto.bc" -o "$IR/mosquitto_ssa.bc"

python3 helper_scripts/compile_database.py \
  "$BASELINE/compile_commands.json" output/mosquitto-ast \
  --plugin build/src/libASTPass.so --target mosquitto --ast-only

bash scripts/setup_svf.sh > output/logs/mosquitto-svf-setup.log
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
"$SVF_ROOT/Release-build/bin/wpa" -print-fp -ander "$IR/mosquitto.bc" \
  > "$IR/fp.txt" 2> output/logs/mosquitto-svf-wpa.stderr
python3 helper_scripts/indirect_callgraph.py "$IR/fp.txt" "$IR/ffp.txt"

python3 - <<'PY'
import hashlib, json, os, subprocess
from pathlib import Path
root = Path('/workspace')
svf = Path(os.environ.get('SVF_ROOT', '/workspace/output/vendor/SVF-2.9'))
ir = root / 'output/mosquitto-ir'
raw, parsed = ir / 'fp.txt', ir / 'ffp.txt'
wpa = svf / 'Release-build/bin/wpa'
meta = {
    'tool': 'SVF', 'tag': 'SVF-2.9', 'gllvm': 'v1.3.1',
    'commit': subprocess.check_output(['git', '-C', str(svf), 'rev-parse', 'HEAD'], text=True).strip(),
    'binary': str(wpa),
    'command': [str(wpa), '-print-fp', '-ander', 'output/mosquitto-ir/mosquitto.bc'],
    'raw_report': 'output/mosquitto-ir/fp.txt',
    'parsed_report': 'output/mosquitto-ir/ffp.txt',
    'raw_report_sha256': hashlib.sha256(raw.read_bytes()).hexdigest(),
    'parsed_report_sha256': hashlib.sha256(parsed.read_bytes()).hexdigest(),
    'parsed_records': sum(1 for line in parsed.read_text().splitlines() if line.strip()),
}
(ir / 'svf_metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps(meta, indent=2))
PY

PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE="$IR/ffp.txt" \
PROTOCOLGUARD_OUTPUT_DIR=output/mosquitto-analysis \
opt-14 -load-pass-plugin build/src/libAnalyzerPass.so \
  -passes=analyzer-pass "$IR/mosquitto_ssa.bc" -disable-output \
  2>&1 | tee output/logs/mosquitto-analysis.log
