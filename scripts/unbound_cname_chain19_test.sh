#!/usr/bin/env bash
# Unbound 19-Level CNAME Chain Test
# Scenario: NS→CNAME(19级)→A, test if Unbound fully traces the chain
# or hits a limit partway through
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cname-chain19-test"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*5355" 2>/dev/null || true
  pkill -f "unbound.*5353\|unbound-binary" 2>/dev/null || true
  sleep 1
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Unbound 19-Level CNAME Chain Test                      ║"
echo "║  Does Unbound fully trace all 19 levels?                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══ Step 1: Python auth server with 19-level CNAME chain ═══
echo ""
echo "═══ Step 1: Building Python auth server with 19-level CNAME chain ═══"

cat > "$VDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
"""Authoritative DNS server with 19-level CNAME chain + query logging."""

import socket, struct, time, sys, json, threading, os

LOG_FILE = "/workspace/output/unbound-cname-chain19-test/auth_queries.jsonl"
CHAIN_DEPTH = 19  # ns1 → c18 → c17 → ... → c0 → A

def dns_encode_name(name):
    result = b''
    for label in name.rstrip('.').split('.'):
        result += bytes([len(label)]) + label.encode('ascii')
    result += b'\x00'
    return result

class QueryLogger:
    def __init__(self):
        self.queries = []
        self.lock = threading.Lock()

    def log(self, qname, qtype, source, response_size=0):
        entry = {
            'timestamp': time.monotonic(),
            'qname': qname,
            'qtype': qtype,
            'source': source,
            'resp_size': response_size
        }
        with self.lock:
            self.queries.append(entry)

    def save(self):
        with self.lock:
            with open(LOG_FILE, 'w') as f:
                for q in self.queries:
                    f.write(json.dumps(q) + '\n')
            return len(self.queries)

    def get_queries(self):
        with self.lock:
            return list(self.queries)

logger = QueryLogger()

# Build zone: c19.com
# NS = ns1.c19.com
# ns1.c19.com CNAME → c18.c19.com
# c18.c19.com CNAME → c17.c19.com
# ...
# c1.c19.com CNAME → c0.c19.com
# c0.c19.com A → 127.0.0.1

def build_chain_zone():
    """Build zone data for c19.com with 19-level CNAME chain."""
    records = {}  # (qname_lower, qtype) -> [(ttl, rdata_wire)]

    zone = 'c19.com'

    # SOA
    soa_rdata = (
        dns_encode_name(f'ns1.{zone}') +
        dns_encode_name(f'admin.{zone}') +
        struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
    )
    records[(zone, 6)] = [(300, soa_rdata)]

    # NS
    records[(zone, 2)] = [(300, dns_encode_name(f'ns1.{zone}'))]

    # 19-level CNAME chain: ns1 → c18 → c17 → ... → c0
    # ns1.c19.com CNAME c18.c19.com
    records[(f'ns1.{zone}', 5)] = [(300, dns_encode_name(f'c18.{zone}'))]

    # c18 → c17, c17 → c16, ..., c1 → c0
    for i in range(18, 0, -1):
        src = f'c{i}.{zone}'
        dst = f'c{i-1}.{zone}'
        records[(src, 5)] = [(300, dns_encode_name(dst))]

    # c0.c19.com A 127.0.0.1 (terminal record)
    records[(f'c0.{zone}', 1)] = [(300, struct.pack('!I', 0x7f000001))]

    return records, zone

# Build zone: short.com (control: 2-level CNAME chain)
def build_short_zone():
    records = {}
    zone = 'short.com'

    soa_rdata = (
        dns_encode_name(f'ns1.{zone}') +
        dns_encode_name(f'admin.{zone}') +
        struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
    )
    records[(zone, 6)] = [(300, soa_rdata)]
    records[(zone, 2)] = [(300, dns_encode_name(f'ns1.{zone}'))]

    # ns1 → alias1 → A
    records[(f'ns1.{zone}', 5)] = [(300, dns_encode_name(f'alias1.{zone}'))]
    records[(f'alias1.{zone}', 1)] = [(300, struct.pack('!I', 0x7f000001))]

    return records, zone

# Build zone: direct.com (control: NS with direct A, no CNAME)
def build_direct_zone():
    records = {}
    zone = 'direct.com'

    soa_rdata = (
        dns_encode_name(f'ns1.{zone}') +
        dns_encode_name(f'admin.{zone}') +
        struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
    )
    records[(zone, 6)] = [(300, soa_rdata)]
    records[(zone, 2)] = [(300, dns_encode_name(f'ns1.{zone}'))]
    records[(f'ns1.{zone}', 1)] = [(300, struct.pack('!I', 0x7f000001))]

    return records, zone

ZONES = {}

chain_records, chain_name = build_chain_zone()
ZONES[chain_name] = chain_records

short_records, short_name = build_short_zone()
ZONES[short_name] = short_records

direct_records, direct_name = build_direct_zone()
ZONES[direct_name] = direct_records

def get_zone(qname):
    name = qname.lower()
    for zname, records in ZONES.items():
        if name == zname or name.endswith('.' + zname):
            return records, zname
    return None, None

def build_response(txid, qname, qtype, qclass, zone_records, aa=True):
    flags = 0x8000 | 0x0400  # QR=1, AA=1
    answers = []
    key = (qname.lower(), qtype)
    if key in zone_records:
        for ttl, rdata in zone_records[key]:
            answers.append((qname, qtype, ttl, rdata))
    # Include CNAME if querying non-CNAME type
    if qtype != 5:
        cname_key = (qname.lower(), 5)
        if cname_key in zone_records:
            for ttl, rdata in zone_records[cname_key]:
                answers.append((qname, 5, ttl, rdata))

    header = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    qname_wire = dns_encode_name(qname)
    question = qname_wire + struct.pack('!HH', qtype, qclass)

    answer_section = b''
    for name, rtype, ttl, rdata in answers:
        answer_section += dns_encode_name(name)
        answer_section += struct.pack('!HH', rtype, qclass)
        answer_section += struct.pack('!I', ttl)
        answer_section += struct.pack('!H', len(rdata))
        answer_section += rdata

    return header + question + answer_section

QTYPE_MAP = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 28:'AAAA', 255:'ANY'}

def handle_query(data, addr, sock):
    if len(data) < 12:
        return
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if (flags >> 15) != 0:
        return

    offset = 12
    labels = []
    while offset < len(data) and data[offset] != 0:
        label_len = data[offset]
        if label_len == 0 or offset + 1 + label_len > len(data):
            break
        labels.append(data[offset+1:offset+1+label_len].decode('ascii', errors='replace'))
        offset += 1 + label_len

    qname = '.'.join(labels)
    if offset + 5 <= len(data):
        qtype, qclass = struct.unpack('!HH', data[offset+1:offset+5])
    else:
        return

    qtype_name = QTYPE_MAP.get(qtype, f'TYPE{qtype}')

    zone_records, zname = get_zone(qname)
    if zone_records is None:
        resp = struct.pack('!HHHHHH', txid, 0x8005, qdcount, 0, 0, 0)
        resp += dns_encode_name(qname) + struct.pack('!HH', qtype, qclass)
        sock.sendto(resp, addr)
        logger.log(qname, qtype_name, 'unbound', 0)
        return

    resp = build_response(txid, qname, qtype, qclass, zone_records)
    sock.sendto(resp, addr)
    logger.log(qname, qtype_name, 'unbound', len(resp))

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 5355))
    print(f"[AUTH] DNS server on 127.0.0.1:5355", flush=True)
    print(f"[AUTH] Zones: {', '.join(ZONES.keys())}", flush=True)
    print(f"[AUTH] Chain depth: 19 (ns1.c19.com → c18 → ... → c0 → A)", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            handle_query(data, addr, sock)
        except Exception as e:
            print(f"[AUTH] Error: {e}", flush=True)

run_server()
PYEOF

python3 "$VDIR/auth_server.py" > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
echo "  Auth server started (PID=$AUTH_PID)"

# Quick test auth server
echo "  Direct test: ns1.c19.com CNAME"
dig @127.0.0.1 -p 5355 ns1.c19.com CNAME +time=3 +noall +answer 2>&1
echo "  Direct test: c0.c19.com A"
dig @127.0.0.1 -p 5355 c0.c19.com A +time=3 +noall +answer 2>&1

# ═══ Step 2: Unbound ═══
echo ""
echo "═══ Step 2: Starting Unbound ═══"

cat > "$VDIR/ub.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cname-chain19-test"
    pidfile: "/workspace/output/unbound-cname-chain19-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cname-chain19-test/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    domain-insecure: "c19.com"
    domain-insecure: "short.com"
    domain-insecure: "direct.com"
    do-not-query-localhost: no

forward-zone:
    name: "c19.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "short.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "direct.com"
    forward-addr: 127.0.0.1@5355

remote-control:
    control-enable: no
EOF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 2

if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID)"
else
  echo "  Unbound FAILED. Log:"
  cat "$VDIR/unbound.log" | head -20
  kill_all
  exit 1
fi

# ═══ Step 3: Queries with precise timing ═══
echo ""
echo "═══ Step 3: Testing 19-level CNAME chain resolution ═══"

python3 << 'PYEOF'
import socket, struct, time, json, os

def dns_query(name, qtype, server='127.0.0.1', port=5353, timeout=30):
    qname = b''
    for label in name.rstrip('.').split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    txid = 0xCAFE
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
            return rcode_map.get(rcode, f'RCODE{rcode}'), elapsed_ms, ans_count, len(data)
        return 'PARSE_ERR', elapsed_ms, 0, 0
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0, 0
    finally:
        sock.close()

QT_A, QT_NS, QT_CNAME = 1, 2, 5
LOG = "/workspace/output/unbound-cname-chain19-test/auth_queries.jsonl"

# Clear previous log
open(LOG, 'w').close()

# Test 1: Direct zone (baseline, no CNAME)
print("  ─── Test 1: direct.com (baseline, NS→A, no CNAME) ───")
rcode, ms, ans, sz = dns_query("direct.com", QT_NS, timeout=10)
print(f"  direct.com NS: {rcode} {ms:.1f}ms ({ans} answers)")
rcode, ms, ans, sz = dns_query("ns1.direct.com", QT_A, timeout=10)
print(f"  ns1.direct.com A: {rcode} {ms:.1f}ms ({ans} answers)")
print()

# Wait for Unbound to flush queries
time.sleep(1)
direct_queries = []
with open(LOG) as f:
    for line in f:
        if line.strip():
            direct_queries.append(json.loads(line))

# Clear log
open(LOG, 'w').close()

# Test 2: Short chain (2-level CNAME)
print("  ─── Test 2: short.com (2-level CNAME: ns1→alias1→A) ───")
rcode, ms, ans, sz = dns_query("short.com", QT_NS, timeout=10)
print(f"  short.com NS: {rcode} {ms:.1f}ms ({ans} answers)")
rcode, ms, ans, sz = dns_query("ns1.short.com", QT_A, timeout=10)
print(f"  ns1.short.com A: {rcode} {ms:.1f}ms ({ans} answers)")
print()

time.sleep(1)
short_queries = []
with open(LOG) as f:
    for line in f:
        if line.strip():
            short_queries.append(json.loads(line))

# Clear log
open(LOG, 'w').close()

# Test 3: 19-level CNAME chain
print("  ─── Test 3: c19.com (19-level CNAME: ns1→c18→c17→...→c0→A) ───")
print("  Sending ns1.c19.com A query (must follow entire CNAME chain)...")

start_total = time.monotonic()
rcode, ms, ans, sz = dns_query("ns1.c19.com", QT_A, timeout=30)
total_elapsed = (time.monotonic() - start_total) * 1000
print(f"  ns1.c19.com A: {rcode} {ms:.1f}ms ({ans} answers, {sz} bytes)")

# Also try querying the zone itself
rcode2, ms2, ans2, sz2 = dns_query("c19.com", QT_NS, timeout=30)
print(f"  c19.com NS: {rcode2} {ms2:.1f}ms ({ans2} answers)")
print()

time.sleep(1)
chain19_queries = []
with open(LOG) as f:
    for line in f:
        if line.strip():
            chain19_queries.append(json.loads(line))

# ═══ Analyze auth server query log ═══
print("  ─── Auth Server Query Analysis ───")
print()

def analyze_queries(queries, label):
    if not queries:
        print(f"  {label}: No queries received by auth server!")
        return

    # Sort by timestamp
    queries.sort(key=lambda q: q['timestamp'])
    t0 = queries[0]['timestamp']

    print(f"  {label}: {len(queries)} queries received from Unbound")
    print(f"  {'#':>3} | {'Query Name':<30} | {'Type':<8} | {'Time(ms)':>10} | {'Δ(ms)':>8}")
    print("  " + "-" * 75)

    for i, q in enumerate(queries):
        rel_ms = (q['timestamp'] - t0) * 1000
        delta = ((q['timestamp'] - queries[i-1]['timestamp']) * 1000) if i > 0 else 0
        print(f"  {i+1:3d} | {q['qname']:<30} | {q['qtype']:<8} | {rel_ms:>10.1f} | {delta:>8.1f}")

    # Check which CNAME levels were resolved
    cnames_resolved = set()
    for q in queries:
        name = q['qname'].lower()
        if name.startswith('c') and name.endswith('.c19.com'):
            try:
                level = int(name.split('.')[0][1:])
                cnames_resolved.add(level)
            except ValueError:
                pass
        elif name == 'ns1.c19.com':
            cnames_resolved.add(19)  # starting point

    if cnames_resolved:
        max_resolved = max(cnames_resolved)
        min_resolved = min(cnames_resolved)
        all_expected = set(range(0, 19))
        missing = all_expected - cnames_resolved
        print()
        print(f"  CNAME levels resolved: {sorted(cnames_resolved)}")
        print(f"  Deepest level reached: c{max_resolved}.c19.com" if max_resolved >= 0 else "  No CNAME levels resolved")
        if missing:
            print(f"  MISSING levels: {sorted(missing)}")
        print(f"  Chain completeness: {len(cnames_resolved - {19})}/19 CNAME levels actually queried")

    total_time = (queries[-1]['timestamp'] - queries[0]['timestamp']) * 1000
    print(f"  Total auth resolution time: {total_time:.1f}ms")

    return len(queries), total_time

print()
d_count, d_time = analyze_queries(direct_queries, "direct.com")
print()
s_count, s_time = analyze_queries(short_queries, "short.com")
print()
c19_count, c19_time = analyze_queries(chain19_queries, "c19.com (19-level)")

# ═══ Compare timing ═══
print()
print("  ─── Timing Comparison ───")
print(f"  direct.com (no CNAME):    {d_count} queries, {d_time:.1f}ms auth time")
print(f"  short.com  (2-level):     {s_count} queries, {s_time:.1f}ms auth time")
print(f"  c19.com    (19-level):    {c19_count} queries, {c19_time:.1f}ms auth time")

if d_time > 0:
    print(f"  Amplification factor vs direct: {c19_time/d_time:.1f}x")
if s_time > 0:
    print(f"  Amplification factor vs 2-level: {c19_time/s_time:.1f}x")

# ═══ Check if limit was hit ═══
print()
print("  ─── Limit Analysis ───")

# Count unique CNAME queries in chain19
cname_queries = [q for q in chain19_queries if q['qtype'] == 'CNAME' or q['qtype'] == 'A']
unique_cname_targets = set(q['qname'].lower() for q in cname_queries)

print(f"  Unique names queried: {len(unique_cname_targets)}")
print(f"  Expected for full chain: 20 (ns1 + c18..c0 + final A)")
print(f"  Actual: {len(unique_cname_targets)}")

if len(unique_cname_targets) < 20:
    print(f"  ⚠ Unbound did NOT trace the full 19-level chain!")
    print(f"  It stopped after resolving {len(unique_cname_targets)} names.")
    # Which levels were resolved?
    levels = set()
    for n in unique_cname_targets:
        if n.endswith('.c19.com'):
            prefix = n.split('.')[0]
            if prefix.startswith('c'):
                try:
                    levels.add(int(prefix[1:]))
                except ValueError:
                    pass
            elif prefix == 'ns1':
                levels.add(19)
    print(f"  Levels reached: {sorted(levels)}")
    print(f"  Deepest: {max(levels) if levels else 'none'}")
    print()
    print("  INTERPRETATION: Unbound hit its CNAME chain limit before")
    print("  fully resolving all 19 levels. The remaining time was likely")
    print("  spent in retry/wait logic or returning cached partial results.")
else:
    print(f"  ✓ Unbound traced ALL 19 CNAME levels!")
    print(f"  The full chain was resolved within {c19_time:.1f}ms.")
    print()
    print("  INTERPRETATION: No CNAME chain limit was hit in this configuration.")

# ═══ Repeat test to check caching ═══
print()
print("  ─── Repeat Query (caching test) ───")
open(LOG, 'w').close()

rcode, ms, ans, sz = dns_query("ns1.c19.com", QT_A, timeout=15)
print(f"  Repeat ns1.c19.com A: {rcode} {ms:.1f}ms ({ans} answers)")

time.sleep(1)
cached_queries = []
with open(LOG) as f:
    for line in f:
        if line.strip():
            cached_queries.append(json.loads(line))

print(f"  Auth queries on repeat: {len(cached_queries)}")
if len(cached_queries) == 0:
    print("  ✓ Result was fully cached — no auth server queries needed")
elif len(cached_queries) < c19_count:
    print(f"  Partial caching: {len(cached_queries)}/{c19_count} queries still sent")
else:
    print("  No caching benefit — all queries re-sent")

PYEOF

# ═══ Step 4: Unbound log analysis ═══
echo ""
echo "═══ Step 4: Unbound log analysis ═══"

echo ""
echo "  --- CNAME chain related entries ---"
grep -i "cname\|chain\|chase\|depth\|limit\|maximum\|maximum.*query" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

echo ""
echo "  --- c19.com resolution entries ---"
grep -i "c19\.com" "$VDIR/unbound.log" 2>/dev/null | head -50 || echo "  (none)"

echo ""
echo "  --- SERVFAIL/error entries for c19 ---"
grep -i "servfail\|error\|fail" "$VDIR/unbound.log" 2>/dev/null | grep -i "c19" | head -10 || echo "  (none)"

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
echo "║  Summary                                                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Auth server query log saved to: $VDIR/auth_queries.jsonl"
echo "  Check the detailed analysis above for:"
echo "  1. Whether all 19 CNAME levels were queried"
echo "  2. Where Unbound stopped (if it hit a limit)"
echo "  3. Timing breakdown per CNAME level"
echo "  4. Amplification factor vs baseline"

kill_all
kill "$AUTH_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
