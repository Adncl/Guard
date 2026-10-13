#!/usr/bin/env bash
set -euo pipefail
cd /workspace

IR=output/bind9-ir
mkdir -p output/logs output/bind9-analysis

# ─── Step 3: AST metadata (best-effort) ────────────────────────────
echo '=== Step 3: AST metadata (best-effort, BIND9 -Werror may block some files) ==='
python3 helper_scripts/compile_database.py \
    /workspace/output/bind9-compile_commands.json output/bind9-ast \
    --plugin build/src/libASTPass.so --target '' --ast-only 2>&1 | tail -10 || {
    echo "WARNING: AST pass had errors (expected with BIND9 -Werror). Continuing..."
}

# ─── Step 4: SVF-2.9 Andersen indirect-call analysis ───────────────
echo '=== Step 4: SVF analysis ==='
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
"$SVF_ROOT/Release-build/bin/wpa" -print-fp -ander /workspace/"$IR"/bind9.bc \
    > /workspace/"$IR"/fp.txt 2> /workspace/output/logs/bind9-svf-wpa.stderr
echo "WPA done, parsing indirect call graph..."
python3 helper_scripts/indirect_callgraph.py /workspace/"$IR"/fp.txt /workspace/"$IR"/ffp.txt
echo "ffp.txt records: $(wc -l < /workspace/$IR/ffp.txt)"

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

# ─── Step 5: Analyzer pass ─────────────────────────────────────────
echo '=== Step 5: Analyzer pass ==='
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
