#!/usr/bin/env bash
set -euo pipefail
cd /workspace
PROTOCOLGUARD_REQUIRE_SVF=1 WPA_REPORT_FILE=output/unbound-ir/ffp.txt \
PROTOCOLGUARD_OUTPUT_DIR=output/unbound-analysis \
opt-14 -load-pass-plugin build/src/libMatchPass.so \
  '-passes=match-pass<config=config/unbound-dnssec.toml>' \
  output/unbound-ir/unbound_ssa.bc -disable-output
