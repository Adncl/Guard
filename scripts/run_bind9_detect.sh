#!/usr/bin/env bash
set -euo pipefail
cd /workspace

# Load API key
set -a
eval "$(sed 's/\r$//' /workspace/.env/endot)"
set +a

echo "OPENAI_API_KEY is set: ${OPENAI_API_KEY:+YES}"
mkdir -p output/logs

# ─── Stage: detect ──────────────────────────────────────────────────
echo '=== Stage: detect ==='
python3 inconsistency_detection/violation_check.py --config config/bind9.toml \
    2>&1 | tee output/logs/bind9-detection.log
