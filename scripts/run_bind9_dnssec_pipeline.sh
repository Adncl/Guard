#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Load API key
set -a
eval "$(sed 's/\r$//' /workspace/.env/endot)"
set +a

echo "OPENAI_API_KEY is set: ${OPENAI_API_KEY:+YES}"
mkdir -p output/logs output/bind9-dnssec-analysis

# ─── Stage 1: LLM-guided slicing (DNSSEC rules) ────────────────────
echo '=== Stage 1: DNSSEC Slicing ==='
PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/bind9-ir/ffp.txt \
PROTOCOLGUARD_OUTPUT_DIR=output/bind9-dnssec-analysis \
opt-14 -load-pass-plugin build/src/libMatchPass.so \
  '-passes=match-pass<config=config/bind9-dnssec.toml>' \
  output/bind9-ir/bind9_ssa.bc -disable-output 2>&1 | tee output/logs/bind9-dnssec-slicing.log

echo '=== Stage 1 complete ==='

# ─── Stage 2: Inconsistency Detection ───────────────────────────────
echo '=== Stage 2: DNSSEC Detection ==='
python3 inconsistency_detection/violation_check.py --config config/bind9-dnssec.toml \
    2>&1 | tee output/logs/bind9-dnssec-detection.log

echo '=== Stage 2 complete ==='
echo '=== BIND9 DNSSEC pipeline finished ==='
