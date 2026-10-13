#!/usr/bin/env bash
set -euo pipefail

export LD_LIBRARY_PATH=/workspace/output/bind9-install/lib/x86_64-linux-gnu
WORKDIR=/workspace/output/bind9-ns-alias-test
mkdir -p "$WORKDIR"

# ── Write violation zone file (NS target is CNAME) ─────────────────
cat > "$WORKDIR/example.com.zone" << 'EOF'
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 1200 604800 3600 )
@   IN NS  ns1.example.com.
ns1 IN CNAME real.example.com.
real IN A 192.0.2.1
EOF

# ── Write control zone file (NS target is A record, correct) ───────
cat > "$WORKDIR/good.com.zone" << 'EOF'
$ORIGIN good.com.
$TTL 3600
@   IN SOA ns1.good.com. hostmaster.good.com. ( 1 3600 1200 604800 3600 )
@   IN NS  ns1.good.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
EOF

# ── Write named.conf ───────────────────────────────────────────────
cat > "$WORKDIR/named.conf" << CONFEOF
options {
    directory "$WORKDIR";
    listen-on port 5353 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "$WORKDIR/named.pid";
    allow-query { any; };
    recursion no;
};

zone "example.com" IN {
    type master;
    file "$WORKDIR/example.com.zone";
};

zone "good.com" IN {
    type master;
    file "$WORKDIR/good.com.zone";
};
CONFEOF

echo '=== Configuration files created ==='
echo '--- example.com.zone (NS->CNAME violation) ---'
cat "$WORKDIR/example.com.zone"
echo '--- good.com.zone (control, NS->A correct) ---'
cat "$WORKDIR/good.com.zone"

# ── Start named ─────────────────────────────────────────────────────
echo ''
echo '=== Starting BIND9 named with NS->CNAME zone ==='
NAMED=/workspace/output/bind9-install/sbin/named

# Run named in foreground, capture all output
cd "$WORKDIR"
timeout 8 "$NAMED" -c "$WORKDIR/named.conf" -g -f 2>&1 | tee "$WORKDIR/named-output.log" &
NAMED_PID=$!

# Wait for named to start or fail
sleep 5

# Check named status
if kill -0 $NAMED_PID 2>/dev/null; then
    NAMED_STATUS="RUNNING"
else
    wait $NAMED_PID 2>/dev/null
    EXIT_CODE=$?
    NAMED_STATUS="EXITED (code $EXIT_CODE)"
fi

echo ''
echo "=== named process status: $NAMED_STATUS ==="

# ── Print the full log ──────────────────────────────────────────────
echo '=== named log output ==='
cat "$WORKDIR/named-output.log"

# ── Check for rejection keywords ────────────────────────────────────
echo ''
echo '=== Checking for RFC 2181 compliance signals ==='
LOG=$(cat "$WORKDIR/named-output.log")
if echo "$LOG" | grep -iq 'CNAME.*other\|NS.*CNAME\|CNAME at\|ignored\|not at apex\|is a CNAME\|points to CNAME\|zone.*failed\|loading.*failed\|could not'; then
    echo '>>> REJECTION DETECTED in log:'
    echo "$LOG" | grep -i 'CNAME.*other\|NS.*CNAME\|CNAME at\|ignored\|not at apex\|is a CNAME\|points to CNAME\|zone.*failed\|loading.*failed\|could not'
else
    echo '>>> No rejection keywords found in log'
fi

# ── Try DNS query if named is running ───────────────────────────────
if [ "$NAMED_STATUS" = "RUNNING" ]; then
    echo ''
    echo '=== Sending DNS queries (named is running) ==='
    apt-get install -y --no-install-recommends dnsutils 2>/dev/null | tail -1

    echo '--- NS example.com ---'
    dig @127.0.0.1 -p 5353 NS example.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'

    echo '--- A ns1.example.com (CNAME alias) ---'
    dig @127.0.0.1 -p 5353 A ns1.example.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'

    echo '--- A www.good.com (control zone) ---'
    dig @127.0.0.1 -p 5353 A www.good.com +tcp +time=2 2>&1 | head -20 || echo 'query failed'
fi

# Cleanup
kill $NAMED_PID 2>/dev/null || true
wait $NAMED_PID 2>/dev/null || true

echo ''
echo '=== Test complete ==='
