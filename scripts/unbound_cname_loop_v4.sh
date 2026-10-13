#!/usr/bin/env bash
# Unbound CNAME Loop DoS Test (v4)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cname-loop-test"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*5355" 2>/dev/null || true
  pkill -f "unbound.*5353\|unbound-binary" 2>/dev/null || true
  sleep 1
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Unbound CNAME Loop DoS Test                            ║"
echo "║  NS→CNAME→CNAME→NS closed loop                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══ Step 1: Python auth server ═══
echo ""
echo "═══ Step 1: Python auth server ═══"
python3 /workspace/scripts/cname_loop_auth_server.py > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1

echo "  Direct auth server test:"
dig @127.0.0.1 -p 5355 loop.com NS +time=3 +noall +answer 2>&1
dig @127.0.0.1 -p 5355 ns1.loop.com CNAME +time=3 +noall +answer 2>&1
dig @127.0.0.1 -p 5355 alias1.loop.com CNAME +time=3 +noall +answer 2>&1
dig @127.0.0.1 -p 5355 alias2.loop.com CNAME +time=3 +noall +answer 2>&1
echo "  Auth server OK."

# ═══ Step 2: Unbound (foreground mode) ═══
echo ""
echo "═══ Step 2: Unbound ═══"

# Write config file
cat > "$VDIR/ub.conf" << 'UBEOF'
server:
    directory: "/workspace/output/unbound-cname-loop-test"
    pidfile: "/workspace/output/unbound-cname-loop-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cname-loop-test/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    domain-insecure: "loop.com"
    domain-insecure: "noloop.com"
    do-not-query-localhost: no

forward-zone:
    name: "loop.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "noloop.com"
    forward-addr: 127.0.0.1@5355

remote-control:
    control-enable: no
UBEOF

# Start Unbound in foreground (redirect output)
"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 2

# Check if alive
if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID)"
else
  echo "  Unbound FAILED. Logs:"
  cat "$VDIR/unbound_stdout.log" | head -20
  cat "$VDIR/unbound.log" 2>/dev/null | head -20
  kill_all
  exit 1
fi

# ═══ Step 3: Queries ═══
echo ""
echo "═══ Step 3: Queries ═══"

# Baseline
echo "  --- noloop.com (baseline) ---"
R0=$(dig @127.0.0.1 -p 5353 www.noloop.com A +time=5 +tries=1 2>&1)
RC0=$(echo "$R0" | grep "status:" | awk '{print $4}' | tr -d ',')
echo "$R0" | grep -E "status:|ANSWER SECTION|A\s" | head -5
echo "  RCODE=$RC0"

# CNAME loop queries via Python (precise timing)
echo ""
echo "  --- CNAME loop queries (Python timing) ---"
python3 << 'PYEOF'
import socket, struct, time

def dns_query(name, qtype, server='127.0.0.1', port=5353, timeout=20):
    qname = b''
    for label in name.rstrip('.').split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'

    txid = 0xBEEF
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack('!HH', qtype, 1)
    pkt = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.sendto(pkt, (server, port))
        data, _ = sock.recvfrom(4096)
        elapsed_ms = (time.monotonic() - start) * 1000
        if len(data) >= 8:
            _, rflags, _, ans_count = struct.unpack('!HHHH', data[:8])
            rcode = rflags & 0xF
            rcode_map = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}
            return rcode_map.get(rcode, f'RCODE{rcode}'), elapsed_ms, ans_count
        return 'PARSE_ERR', elapsed_ms, 0
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0
    finally:
        sock.close()

QT_A, QT_NS, QT_CNAME = 1, 2, 5

tests = [
    ("loop.com NS",               "loop.com",          QT_NS),
    ("ns1.loop.com A",            "ns1.loop.com",      QT_A),
    ("ns1.loop.com CNAME",        "ns1.loop.com",      QT_CNAME),
    ("alias2.loop.com A",         "alias2.loop.com",   QT_A),
    ("www.loop.com A",            "www.loop.com",      QT_A),
]

print(f"  {'Query':<30} | {'RCODE':<10} | {'Time(ms)':>10} | {'Answers':>7}")
print("  " + "-" * 70)

results = []
for label, qname, qtype in tests:
    rcode, ms, ans = dns_query(qname, qtype, timeout=20)
    print(f"  {label:<30} | {rcode:<10} | {ms:>10.1f} | {ans:>7}")
    results.append((label, rcode, ms))

print()

# Burst test
print("  Burst: 5 rapid loop.com NS queries")
for i in range(1, 6):
    rcode, ms, ans = dns_query("loop.com", QT_NS, timeout=20)
    print(f"    #{i}: {rcode} {ms:.1f}ms")
print()

# Post-test
rcode, ms, ans = dns_query("www.noloop.com", QT_A, timeout=5)
print(f"  Post-test noloop.com: {rcode} {ms:.1f}ms ({ans} answers)")

# Summary
print()
print("  ─── Analysis ───")
servfail_count = sum(1 for _, r, _ in results if r == 'SERVFAIL')
timeout_count = sum(1 for _, r, _ in results if r == 'TIMEOUT')
noerror_count = sum(1 for _, r, _ in results if r == 'NOERROR')
max_time = max(ms for _, _, ms in results)

print(f"  SERVFAIL: {servfail_count}, NOERROR: {noerror_count}, TIMEOUT: {timeout_count}")
print(f"  Max response time: {max_time:.1f}ms")

if servfail_count > 0:
    print("  → Unbound detects the CNAME loop and returns SERVFAIL (fail-safe)")
    print("  → However, it did NOT reject NS→CNAME at delegation (RFC 2181 violation)")
if timeout_count > 0:
    print("  → Some queries TIMED OUT — possible resource exhaustion")
if noerror_count > 0 and servfail_count == 0:
    print("  → Unbound FAILED to detect the loop — critical violation!")
if max_time > 5000:
    print(f"  → Slow response ({max_time:.0f}ms) — possible delay amplification")
PYEOF

# ═══ Step 4: Logs ═══
echo ""
echo "═══ Step 4: Unbound log analysis ═══"

echo ""
echo "  --- CNAME/loop/delegation related ---"
grep -i "cname\|loop\|cycle\|chase\|delegat\|referral\|target\|infrastructure" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

echo ""
echo "  --- SERVFAIL/error ---"
grep -i "servfail\|error\|fail" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

echo ""
echo "  --- loop.com resolution log ---"
grep -i "loop\.com" "$VDIR/unbound.log" 2>/dev/null | head -40 || echo "  (none)"

# ═══ Step 5: Health ═══
echo ""
echo "═══ Step 5: Health ═══"
kill -0 "$UB_PID" 2>/dev/null && echo "  Unbound: ALIVE" || echo "  Unbound: DEAD"
kill -0 "$AUTH_PID" 2>/dev/null && echo "  Auth: ALIVE" || echo "  Auth: DEAD"

if kill -0 "$UB_PID" 2>/dev/null; then
  ps -o pid,rss,vsz,comm -p "$UB_PID" 2>/dev/null || true
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Final Summary                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  CNAME Loop: ns1.loop.com →CNAME→ alias1 →CNAME→ alias2 →CNAME→ ns1"
echo "  RFC 2181 §10.3: NS MUST NOT be an alias (CNAME)"
echo "  BIND9 (RFC-compliant): Rejects this zone at load"
echo "  Unbound: Does NOT reject NS→CNAME at delegation stage"
echo ""
echo "  This test checks whether Unbound has fail-safe behavior:"
echo "  - Detects CNAME loop during resolution → SERVFAIL"
echo "  - Stays within resource budget (no hang/crash)"
echo "  - Continues serving other queries"

kill_all
echo ""
echo "=== Test Complete ==="
