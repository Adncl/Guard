#!/usr/bin/env bash
set -euo pipefail
cd /workspace
mkdir -p output/logs

# The paper's whole-program input is produced by GLLVM and then analyzed by
# the released SVF-2.9 Andersen implementation.  Keep the ordinary Clang
# build as the runnable baseline used by replay, while maintaining a separate
# GLLVM build solely for the analysis bitcode.
cmake -S program_slicing -B build -G Ninja \
  -DLLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-14/lib/cmake/clang \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 2
python3 scripts/prepare_sol.py
cmake -S output/sol-source -B output/sol-build -G Ninja \
  -DCMAKE_C_COMPILER=clang-14 -DCMAKE_CXX_COMPILER=clang++-14 \
  -DCMAKE_C_FLAGS="-Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable"
cmake --build output/sol-build -j 2

rm -rf output/sol-gllvm-build output/gllvm-store
mkdir -p output/gllvm-store
LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin \
LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++ LLVM_LINK_NAME=llvm-link \
LLVM_AR_NAME=llvm-ar WLLVM_BC_STORE=/workspace/output/gllvm-store \
cmake -S output/sol-source -B output/sol-gllvm-build -G Ninja \
  -DCMAKE_C_COMPILER=gclang -DCMAKE_CXX_COMPILER=gclang++ \
  -DCMAKE_C_FLAGS="-Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable"
LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin \
LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++ LLVM_LINK_NAME=llvm-link \
LLVM_AR_NAME=llvm-ar WLLVM_BC_STORE=/workspace/output/gllvm-store \
cmake --build output/sol-gllvm-build -j 2
LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin LLVM_LINK_NAME=llvm-link LLVM_AR_NAME=llvm-ar \
get-bc -o output/sol-ir/sol.bc output/sol-gllvm-build/sol
opt-14 -passes='mem2reg,loop-mssa(licm)' output/sol-ir/sol.bc -o output/sol-ir/sol_ssa.bc

# Clang AST metadata is retained as a separate concern; it must not overwrite
# the GLLVM bitcode consumed by SVF.
rm -rf output/sol-ast
python3 helper_scripts/compile_database.py output/sol-build/compile_commands.json output/sol-ast --plugin build/src/libASTPass.so

bash scripts/setup_svf.sh > output/logs/svf-setup.log
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
export SVF_ROOT
SVF_WPA="$SVF_ROOT/Release-build/bin/wpa"
WPA_REPORT_FILE=output/sol-ir/ffp.txt
"$SVF_WPA" -print-fp -ander output/sol-ir/sol.bc > output/sol-ir/fp.txt 2> output/logs/svf-wpa.stderr
python3 helper_scripts/indirect_callgraph.py output/sol-ir/fp.txt "$WPA_REPORT_FILE"
python3 - <<'PY'
import hashlib, json, os, subprocess
from pathlib import Path
root = Path('/workspace')
svf_root = Path(os.environ.get('SVF_ROOT', '/workspace/output/vendor/SVF-2.9'))
wpa = svf_root / 'Release-build/bin/wpa'
report = root / 'output/sol-ir/ffp.txt'
meta = {
    'tool': 'SVF', 'tag': 'SVF-2.9', 'gllvm': 'v1.3.1',
    'commit': subprocess.check_output(['git', '-C', str(svf_root), 'rev-parse', 'HEAD'], text=True).strip(),
    'binary': str(wpa),
    'command': [str(wpa), '-print-fp', '-ander', 'output/sol-ir/sol.bc'],
    'raw_report': 'output/sol-ir/fp.txt',
    'parsed_report': 'output/sol-ir/ffp.txt',
    'raw_report_sha256': hashlib.sha256((root/'output/sol-ir/fp.txt').read_bytes()).hexdigest(),
    'parsed_report_sha256': hashlib.sha256(report.read_bytes()).hexdigest(),
    'parsed_records': sum(1 for line in report.read_text().splitlines() if line.strip()),
}
(root/'output/sol-ir/svf_metadata.json').write_text(json.dumps(meta, indent=2)+'\n')
PY

PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE="$WPA_REPORT_FILE" \
PROTOCOLGUARD_OUTPUT_DIR=output/sol-analysis opt-14 -load-pass-plugin build/src/libAnalyzerPass.so \
  -passes=analyzer-pass output/sol-ir/sol_ssa.bc -disable-output
