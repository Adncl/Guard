#!/usr/bin/env bash
set -euo pipefail
cd /workspace
stage=${1:-all}
mkdir -p output/logs
if [[ "$stage" == extract || "$stage" == all ]]; then
  python3 scripts/prepare_mosquitto_rules.py 2>&1 | tee output/logs/mosquitto-extraction.log
fi
if [[ "$stage" == build || "$stage" == all ]]; then
  bash scripts/build_mosquitto.sh 2>&1 | tee output/logs/mosquitto-build.log
fi
if [[ "$stage" == slice || "$stage" == all ]]; then
  PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/mosquitto-ir/ffp.txt \
  PROTOCOLGUARD_OUTPUT_DIR=output/mosquitto-analysis \
  opt-14 -load-pass-plugin build/src/libMatchPass.so \
  '-passes=match-pass<config=config/mosquitto.toml>' \
  output/mosquitto-ir/mosquitto_ssa.bc -disable-output 2>&1 | tee output/logs/mosquitto-slicing.log
fi
if [[ "$stage" == detect || "$stage" == all ]]; then
  python3 inconsistency_detection/violation_check.py --config config/mosquitto.toml \
    2>&1 | tee output/logs/mosquitto-detection.log
fi
if [[ "$stage" == verify || "$stage" == all ]]; then
  python3 -m protocolguard.verification --config config/mosquitto.toml \
    2>&1 | tee output/logs/mosquitto-verification.log
fi
if [[ "$stage" == fuzz || "$stage" == all ]]; then
  python3 scripts/run_fuzz.py --config config/mosquitto.toml \
    2>&1 | tee output/logs/mosquitto-fuzz.log
fi
if [[ "$stage" == test || "$stage" == all ]]; then
  python3 -m unittest discover -s tests -v 2>&1 | tee output/logs/mosquitto-tests.log
fi

