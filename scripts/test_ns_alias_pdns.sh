#!/usr/bin/env bash
set -euo pipefail

# ─── PowerDNS Recursor NS→CNAME wire-level verification ────────────
# Tests whether PowerDNS Recursor accepts or rejects a zone where
# an NS target is a CNAME (RFC 2181 §10.3 violation).

BINARY=/workspace/output/pdns-recursor-binary-baseline
WORKDIR=/workspace/output/pdns-ns-alias-test
mkdir -p "$WORKDIR"

echo "=== PowerDNS Recursor NS→CNAME Wire-Level Verification ==="
echo "Binary: $BINARY"
export LD_LIBRARY_PATH=/workspace/output/pdns-install-baseline/lib:${LD_LIBRARY_PATH:-}
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  liblua5.3-0 libboost-context1.74.0 libboost-system1.74.0 \
  libboost-filesystem1.74.0 libboost-program-options1.74.0 \
  libboost-regex1.74.0 libprotobuf23 libsodium23 libfstrm0 \
  2>/dev/null | tail -1
$BINARY --version 2>&1 | head -1
echo ""

# ─── Write violation zone file (NS target is CNAME) ────────────────
cat > "$WORKDIR/example.com.zone" << 'EOF'
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 1200 604800 3600 )
@   IN NS  ns1.example.com.
ns1 IN CNAME real.example.com.
real IN A 192.0.2.1
EOF

# ─── Write control zone file (NS target is A record) ───────────────
cat > "$WORKDIR/good.com.zone" << 'EOF'
$ORIGIN good.com.
$TTL 3600
@   IN SOA ns1.good.com. hostmaster.good.com. ( 1 3600 1200 604800 3600 )
@   IN NS  ns1.good.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
EOF

# ─── Write recursor config (YAML format required by new versions) ──
# PowerDNS prefixes config name with 'recursor-', so we use 'recursor.yml'
cat > "$WORKDIR/recursor.yml" << 'EOF'
---
incoming:
  port: 5354
  listen:
    - 127.0.0.1
recursor:
  auth_zones:
    - zone: example.com
      file: WORKDIR_PLACEHOLDER/example.com.zone
    - zone: good.com
      file: WORKDIR_PLACEHOLDER/good.com.zone
logging:
  loglevel: 6
EOF
sed -i "s|WORKDIR_PLACEHOLDER|$WORKDIR|g" "$WORKDIR/recursor.yml"
# Also create the prefixed version that PowerDNS looks for
cp "$WORKDIR/recursor.yml" "$WORKDIR/recursor-recursor.yml.conf"

echo '=== Configuration files created ==='
echo '--- example.com.zone (NS→CNAME violation) ---'
cat "$WORKDIR/example.com.zone"
echo '--- good.com.zone (control, NS→A correct) ---'
cat "$WORKDIR/good.com.zone"

# ─── Start pdns_recursor ───────────────────────────────────────────
echo ''
echo '=== Starting PowerDNS Recursor ==='
cd "$WORKDIR"

# Run in foreground, capture output
mkdir -p /var/run/pdns-recursor 2>/dev/null || true
timeout 8 "$BINARY" --config-dir="$WORKDIR" --daemon=no \
    2>&1 | tee "$WORKDIR/recursor-output.log" &
PDNS_PID=$!

# Wait for startup
sleep 4

# Check if process is still running
if kill -0 $PDNS_PID 2>/dev/null; then
    PDNS_STATUS="RUNNING"
else
    wait $PDNS_PID 2>/dev/null
    EXIT_CODE=$?
    PDNS_STATUS="EXITED (code $EXIT_CODE)"
fi

echo ''
echo "=== pdns_recursor process status: $PDNS_STATUS ==="

# ─── Print the full log ────────────────────────────────────────────
echo '=== recursor log output ==='
cat "$WORKDIR/recursor-output.log"

# ─── Check for rejection keywords ──────────────────────────────────
echo ''
echo '=== Checking for RFC 2181 compliance signals ==='
LOG=$(cat "$WORKDIR/recursor-output.log")
if echo "$LOG" | grep -iq 'CNAME.*other\|NS.*CNAME\|CNAME at\|ignored\|is a CNAME\|points to CNAME\|zone.*failed\|loading.*failed\|could not\|refuse\|reject\|error.*zone\|invalid.*zone'; then
    echo '>>> REJECTION DETECTED in log:'
    echo "$LOG" | grep -i 'CNAME.*other\|NS.*CNAME\|CNAME at\|ignored\|is a CNAME\|points to CNAME\|zone.*failed\|loading.*failed\|could not\|refuse\|reject\|error.*zone\|invalid.*zone'
else
    echo '>>> No rejection keywords found in log'
fi

# ─── Try DNS query if recursor is running ──────────────────────────
if [ "$PDNS_STATUS" = "RUNNING" ]; then
    echo ''
    echo '=== Sending DNS queries ==='
    apt-get install -y --no-install-recommends dnsutils 2>/dev/null | tail -1

    echo '--- NS example.com (violation zone) ---'
    dig @127.0.0.1 -p 5354 NS example.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'

    echo '--- A ns1.example.com (CNAME alias in violation zone) ---'
    dig @127.0.0.1 -p 5354 A ns1.example.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'

    echo '--- A www.good.com (control zone) ---'
    dig @127.0.0.1 -p 5354 A www.good.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'
fi

# Cleanup
kill $PDNS_PID 2>/dev/null || true
wait $PDNS_PID 2>/dev/null || true

echo ''
echo '=== Test complete ==='
