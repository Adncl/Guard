#!/usr/bin/env bash
# Unbound CNAME Loop DoS Test (v3)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cname-loop-test"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*auth_server\|python3.*5355" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  rm -f "$VDIR"/*.pid 2>/dev/null || true
  sleep 1
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Unbound CNAME Loop DoS Test (v3)                       ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══ Step 1: Python auth server ═══
echo ""
echo "═══ Step 1: Starting Python authoritative DNS server ═══"
python3 /workspace/scripts/cname_loop_auth_server.py > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
echo "  Auth server PID=$AUTH_PID"

# Quick auth server test
echo "  Testing auth server directly..."
dig @127.0.0.1 -p 5355 loop.com NS +time=3 2>&1 | head -15
echo "---"
dig @127.0.0.1 -p 5355 ns1.loop.com CNAME +time=3 2>&1 | head -15
echo "---"
dig @127.0.0.1 -p 5355 ns1.loop.com A +time=3 2>&1 | head -15
echo "---"
dig @127.0.0.1 -p 5355 www.noloop.com A +time=3 2>&1 | head -15

# ═══ Step 2: Unbound ═══
echo ""
echo "═══ Step 2: Starting Unbound ═══"

# Create unbound user if needed
id unbound 2>/dev/null || useradd -r -s /sbin/nologin unbound 2>/dev/null || true

cat > "$VDIR/unbound.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cname-loop-test"
    pidfile: "/workspace/output/unbound-cname-loop-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    verbosity: 3
    log-queries: yes
    log-replies: yes

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
  echo "  Unbound failed! Log:"
  cat "$VDIR/unbound.log" | head -30
  kill_all
  exit 1
fi

# ═══ Step 3: Queries ═══
echo ""
echo "═══ Step 3: Queries through Unbound ═══"

# Baseline
echo ""
echo "  --- Baseline: noloop.com ---"
dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 2>&1 | head -15

# CNAME loop test
echo ""
echo "  --- Test: loop.com NS query (NS is CNAME→CNAME→NS loop) ---"
echo "  (measuring time with Python)..."
python3 << 'PYEOF'
import socket, struct, time

def dns_query(name, qtype=1, server='127.0.0.1', port=5353, timeout=15):
    """Send a DNS query and measure response time."""
    qname_parts = name.rstrip('.').split('.')
    qname = b''
    for p in qname_parts:
        qname += bytes([len(p)]) + p.encode()
    qname += b'\x00'

    txid = 0xCAFE
    flags = 0x0100  # RD=1
    header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    question = qname + struct.pack('!HH', qtype, 1)  # class IN

    pkt = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    start = time.monotonic()
    try:
        sock.sendto(pkt, (server, port))
        data, addr = sock.recvfrom(4096)
        elapsed = (time.monotonic() - start) * 1000  # ms

        if len(data) >= 12:
            rtxid, rflags, rqd, ran = struct.unpack('!HHHH', data[:8])
            rcode = rflags & 0xF
            aa = (rflags >> 10) & 1
            tc = (rflags >> 9) & 1
            rd = (rflags >> 8) & 1
            ra = (rflags >> 7) & 1
            ad = (rflags >> 5) & 1
            cd = (rflags >> 4) & 1
            rcode_names = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}
            rcode_name = rcode_names.get(rcode, f'RCODE{rcode}')
            print(f"  Response: {rcode_name} (rcode={rcode}), AA={aa}, RA={ra}")
            print(f"  Answers: {ran}, Elapsed: {elapsed:.1f}ms")
            return rcode, elapsed, ran
    except socket.timeout:
        elapsed = (time.monotonic() - start) * 1000
        print(f"  TIMEOUT after {elapsed:.1f}ms")
        return -1, elapsed, 0
    finally:
        sock.close()

# QTYPE constants
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5

print()
print("  Test 1: noloop.com A (baseline, no loop)")
rcode, ms, ans = dns_query('www.noloop.com', QTYPE_A)
print()

print("  Test 2: loop.com NS (NS is CNAME→CNAME→NS loop)")
rcode, ms, ans = dns_query('loop.com', QTYPE_NS)
print()

print("  Test 3: ns1.loop.com A (resolve the CNAME-looped nameserver)")
rcode, ms, ans = dns_query('ns1.loop.com', QTYPE_A)
print()

print("  Test 4: ns1.loop.com CNAME (direct CNAME query)")
rcode, ms, ans = dns_query('ns1.loop.com', QTYPE_CNAME)
print()

print("  Test 5: alias2.loop.com A (query the CNAME that loops back)")
rcode, ms, ans = dns_query('alias2.loop.com', QTYPE_A)
print()

# Burst test
print("  Test 6: Burst of 5 queries to loop.com NS")
for i in range(1, 6):
    rcode, ms, ans = dns_query('loop.com', QTYPE_NS, timeout=15)
    print(f"    Burst #{i}: rcode={rcode}, {ms:.1f}ms")
print()

# Post-test: still functional?
print("  Test 7: Post-test noloop.com A")
rcode, ms, ans = dns_query('www.noloop.com', QTYPE_A)
print()
PYEOF

# ═══ Step 4: Log analysis ═══
echo ""
echo "═══ Step 4: Log analysis ═══"

echo ""
echo "  --- Auth server log ---"
cat "$VDIR/auth.log" 2>/dev/null | head -40

echo ""
echo "  --- Unbound log: CNAME/loop related ---"
grep -i "cname\|loop\|cycle\|chase\|delegat\|referral\|infrastructure\|target" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

echo ""
echo "  --- Unbound log: SERVFAIL/error ---"
grep -i "servfail\|error\|fail\|timeout\|formerr" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

echo ""
echo "  --- Unbound log: loop.com entries ---"
grep -i "loop\.com" "$VDIR/unbound.log" 2>/dev/null | head -40 || echo "  (none)"

# ═══ Step 5: Health ═══
echo ""
echo "═══ Step 5: Health check ═══"
if [ -f "$VDIR/unbound.pid" ] && kill -0 "$(cat "$VDIR/unbound.pid")" 2>/dev/null; then
  echo "  Unbound: ALIVE"
  ps -o pid,rss,vsz,comm -p "$(cat "$VDIR/unbound.pid")" 2>/dev/null || true
else
  echo "  Unbound: DEAD"
fi
echo "  Auth server: PID=$AUTH_PID"
kill -0 "$AUTH_PID" 2>/dev/null && echo "  Auth: ALIVE" || echo "  Auth: DEAD"

# ═══ Summary ═══
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Summary                                                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Zone: ns1.loop.com→CNAME→alias1→CNAME→alias2→CNAME→ns1 (loop)"
echo "  BIND9 (RFC-compliant): Rejects this zone at load time"
echo "  Unbound (RFC-violating): Does NOT reject NS→CNAME at delegation"
echo ""
echo "  Key questions:"
echo "  1. Does Unbound detect the CNAME loop? → Check RCODE above"
echo "  2. Does Unbound stay within resource budget? → Check elapsed time"
echo "  3. Does Unbound crash or hang? → Check process health"
echo "  4. Can Unbound still serve other queries? → Check post-test"

kill_all
kill "$AUTH_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
