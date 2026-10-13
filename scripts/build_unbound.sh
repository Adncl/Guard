#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Case: Unbound 1.26.0 (DNS). Autoconf project, so the compile database is
# recovered from the real build log instead of CMake's export.
SOURCE=output/unbound-source
IR=output/unbound-ir
STORE=output/unbound-gllvm-store
mkdir -p "$IR" "$STORE" output/logs

COMMON_FLAGS='-Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable'
# NOTE: -Wno-error=implicit-function-declaration must NOT be used with
# configure: it defeats the implicit-declaration errors that autoconf
# function detection relies on (it falsely detects pthread_set_name_np).
ANALYSIS_FLAGS="-g -O0 -Xclang -disable-O0-optnone -fno-discard-value-names $COMMON_FLAGS"

cd "$SOURCE"
chmod +x configure install-sh config.guess config.sub missing compile depcomp ltmain.sh 2>/dev/null || true

# 1) Clang-14 baseline build (replay binary + compile log for the database)
./configure CC=clang-14 CFLAGS="-g -O2 $COMMON_FLAGS" > /workspace/output/logs/unbound-configure.log
make -j2 > /workspace/output/logs/unbound-build.log
cp unbound /workspace/output/unbound-binary-baseline

# 2) Recover compile_commands.json from the libtool build log
python3 - <<'PY'
import json, shlex
from pathlib import Path
records = []
for line in Path('/workspace/output/logs/unbound-build.log').read_text(errors='replace').splitlines():
    if ' -c ' not in line or 'clang-14' not in line:
        continue
    args = shlex.split(line[line.index('clang-14'):])
    # Strip shell redirections that leak into the recovered line.
    args = [a for a in args if not (a in ('>/dev/null', '2>&1', '2>/dev/null', '>&1')
                                    or a.startswith('>') or a.startswith('2>') or a.startswith('&>'))]
    if '-c' not in args:
        continue
    files = [a for a in args if a.endswith('.c') and a != '-c']
    if not files:
        continue
    records.append({'directory': '/workspace/output/unbound-source',
                    'arguments': args, 'file': files[0]})
assert records, 'no compile commands recovered from the build log'
Path('/workspace/output/unbound-compile_commands.json').write_text(json.dumps(records, indent=2))
print(f'recovered {len(records)} compile commands')
PY

# 3) GLLVM whole-program bitcode build
make clean > /dev/null 2>&1 || true
export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin
export LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link-14 LLVM_AR_NAME=llvm-ar-14
export WLLVM_BC_STORE=/workspace/$STORE
./configure CC=gclang CXX=gclang++ CFLAGS="$ANALYSIS_FLAGS" > /workspace/output/logs/unbound-configure-gllvm.log
make -j2 > /workspace/output/logs/unbound-gllvm-build.log
get-bc -o "$IR/unbound.bc" unbound || get-bc -o "$IR/unbound.bc" .libs/unbound
opt-14 -passes='mem2reg,loop-mssa(licm)' "$IR/unbound.bc" -o "$IR/unbound_ssa.bc"

# 4) Clang control-flow (AST) metadata
python3 helper_scripts/compile_database.py \
  output/unbound-compile_commands.json output/unbound-ast \
  --plugin build/src/libASTPass.so --target '' --ast-only

# 5) SVF-2.9 Andersen indirect-call report
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
"$SVF_ROOT/Release-build/bin/wpa" -print-fp -ander "$IR/unbound.bc" \
  > "$IR/fp.txt" 2> output/logs/unbound-svf-wpa.stderr
python3 helper_scripts/indirect_callgraph.py "$IR/fp.txt" "$IR/ffp.txt"

python3 - <<'PY'
import hashlib, json
from pathlib import Path
ir = Path('output/unbound-ir')
meta = {
    'tool': 'SVF', 'tag': 'SVF-2.9',
    'command': ['wpa', '-print-fp', '-ander', 'output/unbound-ir/unbound.bc'],
    'raw_report': 'output/unbound-ir/fp.txt',
    'parsed_report': 'output/unbound-ir/ffp.txt',
    'raw_report_sha256': hashlib.sha256((ir / 'fp.txt').read_bytes()).hexdigest(),
    'parsed_report_sha256': hashlib.sha256((ir / 'ffp.txt').read_bytes()).hexdigest(),
    'parsed_records': sum(1 for line in (ir / 'ffp.txt').read_text().splitlines() if line.strip()),
}
(ir / 'svf_metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps(meta, indent=2))
PY

# 6) Analyzer pass over the whole-program SSA bitcode
PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE="$IR/ffp.txt" \
PROTOCOLGUARD_OUTPUT_DIR=output/unbound-analysis \
opt-14 -load-pass-plugin build/src/libAnalyzerPass.so \
  -passes=analyzer-pass "$IR/unbound_ssa.bc" -disable-output \
  2>&1 | tee output/logs/unbound-analysis.log
