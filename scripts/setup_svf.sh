#!/usr/bin/env bash
set -euo pipefail
cd /workspace

SVF_TAG=${SVF_TAG:-SVF-2.9}
SVF_ROOT=${SVF_ROOT:-/workspace/output/vendor/SVF-2.9}
SVF_WPA="$SVF_ROOT/Release-build/bin/wpa"

mkdir -p "$(dirname "$SVF_ROOT")"
if [[ ! -d "$SVF_ROOT/.git" ]]; then
  rm -rf "$SVF_ROOT"
  git clone --depth 1 --branch "$SVF_TAG" https://github.com/SVF-tools/SVF.git "$SVF_ROOT"
fi

if [[ ! -x "$SVF_WPA" ]]; then
  # SVF-2.9 requires a newer CMake than Ubuntu 22.04 ships.  The image
  # installs it from PyPI and the Z3 package in Ubuntu supplies the solver.
  ln -sf /usr/lib/x86_64-linux-gnu/libz3.so /usr/local/lib/libz3.so
  ln -sf /usr/include/z3++.h /usr/local/include/z3++.h
  cmake --version
  (cd "$SVF_ROOT" && LLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm Z3_DIR=/usr/local ./build.sh)
fi

test -x "$SVF_WPA"
git -C "$SVF_ROOT" rev-parse HEAD
echo "$SVF_WPA"
