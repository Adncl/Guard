#!/usr/bin/env bash
set -euo pipefail
cd /workspace

SOURCE=output/pdns-recursor-source/pdns/recursordist
IR=output/pdns-ir
STORE=output/pdns-gllvm-store
mkdir -p "$IR" "$STORE" output/logs

# Install build dependencies
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  libboost-all-dev libssl-dev libsodium-dev libcap-dev \
  liblua5.3-dev lua5.3 libprotobuf-dev protobuf-compiler \
  libfstrm-dev libsnmp-dev libcurl4-openssl-dev \
  libyaml-cpp-dev pkg-config curl ragel \
  pandoc libsystemd-dev 2>/dev/null | tail -1
pip3 install -q meson ninja 2>/dev/null

# Install Rust toolchain (PowerDNS Recursor requires it)
if ! command -v cargo &>/dev/null; then
  echo 'Installing Rust toolchain...'
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1 | tail -3
  source "$HOME/.cargo/env"
fi
echo "cargo: $(which cargo); rustc: $(rustc --version)"

COMMON_FLAGS='-Wno-deprecated-declarations'
ANALYSIS_FLAGS="-g -O0 -Xclang -disable-O0-optnone -fno-discard-value-names $COMMON_FLAGS"

# ─── Step 1: Baseline build with clang-14 ───────────────────────────
echo '=== Step 1: Baseline build ==='
BLD=output/pdns-baseline-build4
rm -rf "$BLD" output/pdns-install-baseline 2>/dev/null || true
mkdir -p "$BLD"

cd /workspace/"$BLD"
CC=clang-14 CXX=clang++-14 meson setup /workspace/"$SOURCE" \
  --prefix=/workspace/output/pdns-install-baseline \
  -Dbuildtype=debugoptimized \
  2>&1 | tee /workspace/output/logs/pdns-baseline-configure.log | tail -5

ninja -j4 2>&1 | tee /workspace/output/logs/pdns-baseline-build.log | tail -5 || {
  echo "ninja had errors, but checking if pdns_recursor was built..."
}
# Install what we can (ignore doc failures)
ninja install 2>&1 | tee /workspace/output/logs/pdns-baseline-install.log | tail -3 || true

# Copy recursor binary
cp /workspace/output/pdns-install-baseline/sbin/pdns_recursor /workspace/output/pdns-recursor-binary-baseline 2>/dev/null || {
  # Try finding the binary directly from the build dir
  find /workspace/"$BLD" -name 'pdns_recursor' -type f -executable \
    -exec cp {} /workspace/output/pdns-recursor-binary-baseline \; 2>/dev/null
}
if [ ! -f /workspace/output/pdns-recursor-binary-baseline ]; then
  echo "FATAL: pdns_recursor binary not found anywhere!"
  find /workspace/"$BLD" -name 'pdns_recursor' 2>/dev/null
  ls /workspace/output/pdns-install-baseline/sbin/ 2>/dev/null
  exit 1
fi
chmod +x /workspace/output/pdns-recursor-binary-baseline

# Verify binary
/workspace/output/pdns-recursor-binary-baseline --version 2>&1 | head -3

# Save compile_commands.json
cp /workspace/"$BLD"/compile_commands.json /workspace/output/pdns-compile_commands.json 2>/dev/null || {
  find /workspace/"$BLD" -name 'compile_commands.json' -exec cp {} /workspace/output/pdns-compile_commands.json \;
}
echo "compile_commands.json saved: $(wc -l < /workspace/output/pdns-compile_commands.json 2>/dev/null || echo 'N/A') lines"
echo '=== Step 1 done ==='
