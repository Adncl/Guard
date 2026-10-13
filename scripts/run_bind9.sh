#!/usr/bin/env bash
set -euo pipefail
cd /workspace
stage=${1:-all}
mkdir -p output/logs

# Install dependencies for all stages
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
    libuv1-dev liburcu-dev liblmdb-dev libjson-c-dev libnghttp2-dev \
    libmaxminddb-dev libidn2-0-dev libssl-dev libcap-dev libxml2-dev \
    libuv1 liburcu8 liblmdb0 libjson-c5 libnghttp2-14 libmaxminddb0 libidn2-0 \
    dnsutils 2>/dev/null | tail -1
pip3 install -q meson ninja 2>/dev/null
export LD_LIBRARY_PATH=/workspace/output/bind9-install-baseline/lib/x86_64-linux-gnu

if [[ "$stage" == build || "$stage" == all ]]; then
  echo "=== Stage: build ==="
  bash scripts/build_bind9.sh 2>&1 | tee output/logs/bind9-build.log
fi

if [[ "$stage" == slice || "$stage" == all ]]; then
  echo "=== Stage: slice ==="
  PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/bind9-ir/ffp.txt \
  PROTOCOLGUARD_OUTPUT_DIR=output/bind9-analysis \
  opt-14 -load-pass-plugin build/src/libMatchPass.so \
    '-passes=match-pass<config=config/bind9.toml>' \
    output/bind9-ir/bind9_ssa.bc -disable-output 2>&1 | tee output/logs/bind9-slicing.log
fi

if [[ "$stage" == detect || "$stage" == all ]]; then
  echo "=== Stage: detect ==="
  python3 inconsistency_detection/violation_check.py --config config/bind9.toml \
    2>&1 | tee output/logs/bind9-detection.log
fi

if [[ "$stage" == verify || "$stage" == all ]]; then
  echo "=== Stage: verify ==="
  python3 -m protocolguard.verification --config config/bind9.toml \
    2>&1 | tee output/logs/bind9-verification.log
fi

if [[ "$stage" == fuzz || "$stage" == all ]]; then
  echo "=== Stage: fuzz ==="
  python3 scripts/run_fuzz.py --config config/bind9.toml \
    2>&1 | tee output/logs/bind9-fuzz.log
fi

echo "=== All requested stages complete ==="
