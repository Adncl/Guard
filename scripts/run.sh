#!/usr/bin/env bash
set -euo pipefail
cd /workspace
stage=${1:-all}
mkdir -p output/logs
if [[ "$stage" == build || "$stage" == all ]]; then
  bash scripts/build.sh 2>&1 | tee output/logs/build.log
fi
if [[ "$stage" == extract || "$stage" == all ]]; then
  python3 -m protocolguard.extraction --config config/sol.toml --html output/mqtt-v3.1.1.html \
    --output output/rules.json --match 'MQTT-3\.1\.(0-[12]|2-3)' 2>&1 | tee output/logs/extraction.log
fi
if [[ "$stage" == slice || "$stage" == all ]]; then
  PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/sol-ir/ffp.txt \
  PROTOCOLGUARD_OUTPUT_DIR=output/sol-analysis opt-14 -load-pass-plugin build/src/libMatchPass.so \
    '-passes=match-pass<config=config/sol.toml>' output/sol-ir/sol_ssa.bc -disable-output 2>&1 | tee output/logs/slicing.log
fi
if [[ "$stage" == detect || "$stage" == all ]]; then
  python3 inconsistency_detection/violation_check.py --config config/sol.toml 2>&1 | tee output/logs/detection.log
fi
if [[ "$stage" == verify || "$stage" == all ]]; then
  python3 -m protocolguard.verification --config config/sol.toml 2>&1 | tee output/logs/verification.log
fi
if [[ "$stage" == fuzz || "$stage" == all ]]; then
  python3 scripts/run_fuzz.py --config config/sol.toml 2>&1 | tee output/logs/fuzz.log
fi
if [[ "$stage" == test || "$stage" == all ]]; then
  python3 -m unittest discover -s tests -v 2>&1 | tee output/logs/tests.log
fi
