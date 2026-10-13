#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Load API key from .env/endot (strip CR from Windows line endings)
set -a
eval "$(sed 's/\r$//' /workspace/.env/endot)"
set +a

echo "OPENAI_API_KEY is set: ${OPENAI_API_KEY:+YES}"

mkdir -p output/logs

# ─── Step: LLM-guided slicing (MatchPass) ───────────────────────────
echo '=== Stage: slice ==='
PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/bind9-ir/ffp.txt \
PROTOCOLGUARD_OUTPUT_DIR=output/bind9-analysis \
opt-14 -load-pass-plugin build/src/libMatchPass.so \
  '-passes=match-pass<config=config/bind9.toml>' \
  output/bind9-ir/bind9_ssa.bc -disable-output 2>&1 | tee output/logs/bind9-slicing.log
