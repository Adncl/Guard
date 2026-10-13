#!/usr/bin/env bash
# Unbound CNAME Loop DoS Test
# Scenario: NS→CNAME→CNAME→...→NS closed loop
# Goal: Check if Unbound correctly detects the loop and has fail-safe behavior
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq liburcu8 libjson-c5 liblmdb0 dnsutils python3 > /dev/null 2>&1
ldconfig

VDIR="/workspace/output/unbound-cname-loop-test"
mkdir -p "$VDIR"

# Binary paths
UNBOUND="/workspace/output/unbound-binary-baseline"
NAMED="/workspace/output/bind9-install/sbin/named"
export LD_LIBRARY_PATH="/workspace/output/bind9-install/lib/x86_64-linux-gnu"

# ─── Helper Functions ──────────────────────────────────────────────
kill_all() {
  pkill -f "named.*5355" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  rm -f "$VDIR"/*.pid 2>/dev/null || true
  sleep 1
}

wait_for_port() {
  local port=$1 max=30
  for i in $(seq 1 $max); do
    if dig @127.0.0.1 -p "$port" localhost > /dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Unbound CNAME Loop DoS Test                            ║"
echo "║  Zone: NS→CNAME→CNAME→NS closed loop                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══════════════════════════════════════════════════════════════════
# Step 1: Set up authoritative server with CNAME loop zone
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 1: Setting up authoritative server with CNAME loop zone ═══"

cat > "$VDIR/auth.conf" << 'EOF'
options {
    directory "/workspace/output/unbound-cname-loop-test";
    listen-on port 5355 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/unbound-cname-loop-test/named.pid";
    allow-query { any; };
    allow-recursion { none; };
    recursion no;
};

// Zone with NS→CNAME→CNAME→NS loop
zone "loop.com" IN {
    type master;
    file "/workspace/output/unbound-cname-loop-test/loop.com.zone";
};

// Control zone: normal NS (no CNAME)
zone "noloop.com" IN {
    type master;
    file "/workspace/output/unbound-cname-loop-test/noloop.com.zone";
};
EOF

# loop.com: NS → CNAME → CNAME → NS (circular)
cat > "$VDIR/loop.com.zone" << 'EOF'
$ORIGIN loop.com.
$TTL 300
@   IN  SOA ns1.loop.com. admin.loop.com. (
        2026100901 3600 900 604800 86400 )
; NS record points to ns1.loop.com
@   IN  NS  ns1.loop.com.
; ns1 is a CNAME → alias1
ns1 IN  CNAME   alias1.loop.com.
; alias1 is a CNAME → alias2
alias1 IN CNAME alias2.loop.com.
; alias2 loops back to ns1 → CNAME LOOP!
alias2 IN CNAME ns1.loop.com.
EOF

# Control zone: normal NS with A record
cat > "$VDIR/noloop.com.zone" << 'EOF'
$ORIGIN noloop.com.
$TTL 300
@   IN  SOA ns1.noloop.com. admin.noloop.com. (
        2026100901 3600 900 604800 86400 )
@   IN  NS  ns1.noloop.com.
ns1 IN  A   127.0.0.1
www IN  A   10.0.0.1
EOF

echo "  Zone files:"
echo "  --- loop.com.zone ---"
cat "$VDIR/loop.com.zone"
echo ""

# Start authoritative server
echo "  Starting authoritative server (BIND9 on port 5355)..."
timeout 300 "$NAMED" -c "$VDIR/auth.conf" -g -f > "$VDIR/named.log" 2>&1 &
sleep 2

if [ -f "$VDIR/named.pid" ] && kill -0 "$(cat "$VDIR/named.pid")" 2>/dev/null; then
  echo "  Authoritative server started."
  # Check if loop.com zone loaded (it might fail due to NS→CNAME)
  grep -i "loop.com\|cname\|error\|loaded" "$VDIR/named.log" | head -10
else
  echo "  WARNING: Authoritative server may not have started. Checking log..."
  cat "$VDIR/named.log" | head -30
fi

# ═══════════════════════════════════════════════════════════════════
# Step 2: Set up Unbound as recursive resolver
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 2: Setting up Unbound recursive resolver ═══"

cat > "$VDIR/unbound.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cname-loop-test"
    pidfile: "/workspace/output/unbound-cname-loop-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    verbosity: 2
    log-queries: yes
    log-replies: yes
    log-local-actions: yes
    # Limit CNAME chain following
    max-queries-per-resolution: 100
    # Timeout settings
    outgoing-num-tcp: 10
    infra-cache-min-rtt: 50
    # Target fetch behavior
    max-target-fetch-advance: 0

forward-zone:
    name: "."
    forward-addr: 127.0.0.1@5355

# Stub zone to directly reach our authoritative server
stub-zone:
    name: "loop.com"
    stub-addr: 127.0.0.1@5355
stub-zone:
    name: "noloop.com"
    stub-addr: 127.0.0.1@5355

remote-control:
    control-enable: no
EOF

echo "  Starting Unbound on port 5353..."
timeout 300 "$UNBOUND" -c "$VDIR/unbound.conf" > "$VDIR/unbound.log" 2>&1 &
sleep 2

if [ -f "$VDIR/unbound.pid" ] && kill -0 "$(cat "$VDIR/unbound.pid")" 2>/dev/null; then
  echo "  Unbound started."
else
  echo "  WARNING: Unbound may not have started. Checking log..."
  cat "$VDIR/unbound.log" | head -20
fi

# ═══════════════════════════════════════════════════════════════════
# Step 3: Run queries through Unbound
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 3: Testing queries through Unbound ═══"

# Test 1: Control query (noloop.com - should work)
echo ""
echo "  --- Test 1: Control query (noloop.com, no CNAME loop) ---"
dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 +tries=1 2>&1

# Test 2: Query loop.com (NS→CNAME loop)
echo ""
echo "  --- Test 2: CNAME loop query (loop.com, NS→CNAME→CNAME→NS loop) ---"
echo "  Sending A query for www.loop.com..."
RESULT=$(dig @127.0.0.1 -p 5353 www.loop.com A +time=10 +tries=1 2>&1)
echo "$RESULT"

# Extract RCODE and time
RCODE=$(echo "$RESULT" | grep "status:" | awk '{print $4}' | tr -d ',')
QUERY_TIME=$(echo "$RESULT" | grep "Query time:" | awk '{print $4}')
echo "  RCODE: $RCODE, Query time: ${QUERY_TIME}ms"

# Test 3: Query the NS record of loop.com directly
echo ""
echo "  --- Test 3: Direct NS query for loop.com ---"
RESULT2=$(dig @127.0.0.1 -p 5353 loop.com NS +time=10 +tries=1 2>&1)
echo "$RESULT2"
RCODE2=$(echo "$RESULT2" | grep "status:" | awk '{print $4}' | tr -d ',')
QUERY_TIME2=$(echo "$RESULT2" | grep "Query time:" | awk '{print $4}')
echo "  RCODE: $RCODE2, Query time: ${QUERY_TIME2}ms"

# Test 4: Multiple queries to test DoS amplification
echo ""
echo "  --- Test 4: Burst of 5 queries to loop.com ---"
for i in 1 2 3 4 5; do
  START_MS=$(date +%s%3N)
  RESULT3=$(dig @127.0.0.1 -p 5353 www.loop.com A +time=10 +tries=1 2>&1)
  END_MS=$(date +%s%3N)
  ELAPSED=$((END_MS - START_MS))
  RCODE3=$(echo "$RESULT3" | grep "status:" | awk '{print $4}' | tr -d ',')
  echo "  Query $i: RCODE=$RCODE3, elapsed=${ELAPSED}ms"
done

# ═══════════════════════════════════════════════════════════════════
# Step 4: Check Unbound logs for loop detection
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 4: Analyzing Unbound logs ═══"

echo ""
echo "  --- Unbound log entries related to CNAME/loop ---"
grep -i "cname\|loop\|cycle\|recursion\|maximum\|limit\|depth\|infrastructure" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none found)"

echo ""
echo "  --- Unbound log entries related to SERVFAIL/error ---"
grep -i "servfail\|error\|fail\|timeout\|refused" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none found)"

echo ""
echo "  --- Unbound log: resolution details for loop.com ---"
grep -i "loop.com" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none found)"

echo ""
echo "  --- Full Unbound log (last 60 lines) ---"
tail -60 "$VDIR/unbound.log" 2>/dev/null

# ═══════════════════════════════════════════════════════════════════
# Step 5: Check Unbound process status (still running or crashed?)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 5: Process health check ═══"

if [ -f "$VDIR/unbound.pid" ] && kill -0 "$(cat "$VDIR/unbound.pid")" 2>/dev/null; then
  echo "  Unbound process: ALIVE (PID=$(cat "$VDIR/unbound.pid"))"
  # Check memory usage
  ps -o pid,rss,vsz,comm -p "$(cat "$VDIR/unbound.pid")" 2>/dev/null || echo "  (could not get memory info)"
else
  echo "  Unbound process: DEAD or CRASHED"
fi

if [ -f "$VDIR/named.pid" ] && kill -0 "$(cat "$VDIR/named.pid")" 2>/dev/null; then
  echo "  Named process: ALIVE (PID=$(cat "$VDIR/named.pid"))"
else
  echo "  Named process: DEAD"
fi

# Test 6: Check if Unbound can still resolve other domains after the loop test
echo ""
echo "  --- Test 6: Post-test resolution (can Unbound still resolve noloop.com?) ---"
RESULT6=$(dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 +tries=1 2>&1)
RCODE6=$(echo "$RESULT6" | grep "status:" | awk '{print $4}' | tr -d ',')
echo "  Post-test noloop.com query: RCODE=$RCODE6"
echo "$RESULT6" | head -12

# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  CNAME Loop DoS Test Summary                            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Expected RFC-compliant behavior:"
echo "  - RFC 2181 §10.3: NS MUST NOT be a CNAME → zone should be rejected"
echo "  - If zone is accepted, resolver should detect CNAME loop and return SERVFAIL"
echo "  - Resolver should NOT enter infinite loop or crash"
echo "  - Resolver should continue serving other queries normally"
echo ""
echo "  Key observations:"
echo "  - loop.com query RCODE: $RCODE"
echo "  - loop.com NS query RCODE: $RCODE2"
echo "  - Post-test noloop.com RCODE: $RCODE6"
echo ""
echo "  If RCODE=SERVFAIL: Unbound detected the loop (fail-safe, but still accepted"
echo "  the NS→CNAME violation at delegation stage)."
echo "  If RCODE=NOERROR: Unbound failed to detect the loop (critical violation)."
echo "  If process crashed: Unbound has no loop protection (DoS vulnerability)."

kill_all
echo ""
echo "=== Test Complete ==="
