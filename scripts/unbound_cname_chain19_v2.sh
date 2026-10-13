#!/usr/bin/env bash
# Unbound 19-Level CNAME Chain Test (v2)
# Focus: exactly which CNAME levels Unbound queries, and where it stops
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
echo "║  Unbound 19-Level CNAME Chain Test (v2)                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
kill_all

# ═══ Step 1: Python auth server ═══
echo ""
echo "═══ Step 1: Python auth server ═══"

cat > "$VDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, threading

LOG_FILE = "/workspace/output/unbound-cname-chain19-test/auth_queries.jsonl"

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
        self.t0 = None

    def log(self, qname, qtype, resp_size=0):
        now = time.monotonic()
        if self.t0 is None:
            self.t0 = now
        entry = {
            'ts': round((now - self.t0) * 1000, 1),
            'qname': qname,
            'qtype': qtype,
            'size': resp_size
        }
        with self.lock:
            self.queries.append(entry)
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')

logger = QueryLogger()

# Build zones
def build_chain19_zone():
    records = {}
    z = 'c19.com'
    soa = (dns_encode_name(f'ns1.{z}') + dns_encode_name(f'admin.{z}') +
           struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))
    records[(z, 6)] = [(300, soa)]
    records[(z, 2)] = [(300, dns_encode_name(f'ns1.{z}'))]
    # ns1 → c18 → c17 → ... → c0 → A
    records[(f'ns1.{z}', 5)] = [(300, dns_encode_name(f'c18.{z}'))]
    for i in range(18, 0, -1):
        records[(f'c{i}.{z}', 5)] = [(300, dns_encode_name(f'c{i-1}.{z}'))]
    records[(f'c0.{z}', 1)] = [(300, struct.pack('!I', 0x7f000001))]
    return records, z

def build_direct_zone():
    records = {}
    z = 'direct.com'
    soa = (dns_encode_name(f'ns1.{z}') + dns_encode_name(f'admin.{z}') +
           struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))
    records[(z, 6)] = [(300, soa)]
    records[(z, 2)] = [(300, dns_encode_name(f'ns1.{z}'))]
    records[(f'ns1.{z}', 1)] = [(300, struct.pack('!I', 0x7f000001))]
    return records, z

def build_short_zone():
    records = {}
    z = 'short.com'
    soa = (dns_encode_name(f'ns1.{z}') + dns_encode_name(f'admin.{z}') +
           struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))
    records[(z, 6)] = [(300, soa)]
    records[(z, 2)] = [(300, dns_encode_name(f'ns1.{z}'))]
    records[(f'ns1.{z}', 5)] = [(300, dns_encode_name(f'alias1.{z}'))]
    records[(f'alias1.{z}', 1)] = [(300, struct.pack('!I', 0x7f000001))]
    return records, z

ZONES = {}
for builder in [build_chain19_zone, build_direct_zone, build_short_zone]:
    recs, name = builder()
    ZONES[name] = recs

def get_zone(qname):
    name = qname.lower()
    for zname, recs in ZONES.items():
        if name == zname or name.endswith('.' + zname):
            return recs
    return None

def build_response(txid, qname, qtype, qclass, recs):
    flags = 0x8400
    answers = []
    key = (qname.lower(), qtype)
    if key in recs:
        for ttl, rd in recs[key]:
            answers.append((qname, qtype, ttl, rd))
    if qtype != 5:
        ck = (qname.lower(), 5)
        if ck in recs:
            for ttl, rd in recs[ck]:
                answers.append((qname, 5, ttl, rd))
    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = dns_encode_name(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += dns_encode_name(n) + struct.pack('!HH', t, qclass) + struct.pack('!I', ttl) + struct.pack('!H', len(rd)) + rd
    return hdr + q + a

QTYPE_MAP = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 5355))
print(f"[AUTH] Listening on 127.0.0.1:5355, zones: {', '.join(ZONES.keys())}", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        if len(data) < 12: continue
        txid, flags, qdcount = struct.unpack('!HHH', data[:6])
        if (flags >> 15) != 0: continue
        off = 12
        labels = []
        while off < len(data) and data[off] != 0:
            ll = data[off]
            if ll == 0 or off + 1 + ll > len(data): break
            labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
            off += 1 + ll
        qname = '.'.join(labels)
        qt, qc = struct.unpack('!HH', data[off+1:off+5])
        qtn = QTYPE_MAP.get(qt, f'T{qt}')
        recs = get_zone(qname)
        if recs is None:
            resp = struct.pack('!HHHHHH', txid, 0x8005, qdcount, 0, 0, 0)
            resp += dns_encode_name(qname) + struct.pack('!HH', qt, qc)
            sock.sendto(resp, addr)
            logger.log(qname, qtn, 0)
            continue
        resp = build_response(txid, qname, qt, qc, recs)
        sock.sendto(resp, addr)
        logger.log(qname, qtn, len(resp))
    except Exception as e:
        print(f"[AUTH] Error: {e}", flush=True)
PYEOF

# Clear log
> "$VDIR/auth_queries.jsonl"

python3 "$VDIR/auth_server.py" > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1

echo "  Quick test:"
dig @127.0.0.1 -p 5355 ns1.c19.com CNAME +time=3 +noall +answer 2>&1
dig @127.0.0.1 -p 5355 c0.c19.com A +time=3 +noall +answer 2>&1

# ═══ Step 2: Unbound ═══
echo ""
echo "═══ Step 2: Unbound ═══"

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
    domain-insecure: "direct.com"
    domain-insecure: "short.com"
    do-not-query-localhost: no

forward-zone:
    name: "c19.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "direct.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "short.com"
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
  echo "  Unbound FAILED"
  cat "$VDIR/unbound.log" | head -20
  kill_all; exit 1
fi

# ═══ Step 3: Queries ═══
echo ""
echo "═══ Step 3: Resolution Tests ═══"

python3 << 'PYEOF'
import socket, struct, time, json

def dns_query(name, qtype, port=5353, timeout=30):
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
        sock.sendto(pkt, ('127.0.0.1', port))
        data, _ = sock.recvfrom(4096)
        ms = (time.monotonic() - start) * 1000
        if len(data) >= 8:
            _, rflags, _, ans = struct.unpack('!HHHH', data[:8])
            rcode = rflags & 0xF
            rc_map = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}
            return rc_map.get(rcode, f'RC{rcode}'), ms, ans
        return 'ERR', ms, 0
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0
    finally:
        sock.close()

LOG = "/workspace/output/unbound-cname-chain19-test/auth_queries.jsonl"
QT_A, QT_NS, QT_CNAME = 1, 2, 5

# --- Test 1: Baseline (direct.com, no CNAME) ---
open(LOG, 'w').close()
print("  Test 1: direct.com (no CNAME chain)")
rcode, ms, ans = dns_query("ns1.direct.com", QT_A, timeout=10)
time.sleep(1)
direct_q = [json.loads(l) for l in open(LOG) if l.strip()]
print(f"    ns1.direct.com A: {rcode} {ms:.1f}ms, auth queries: {len(direct_q)}")

# --- Test 2: Short chain (2-level) ---
open(LOG, 'w').close()
print("  Test 2: short.com (2-level CNAME)")
rcode, ms, ans = dns_query("ns1.short.com", QT_A, timeout=10)
time.sleep(1)
short_q = [json.loads(l) for l in open(LOG) if l.strip()]
print(f"    ns1.short.com A: {rcode} {ms:.1f}ms, auth queries: {len(short_q)}")

# --- Test 3: 19-level chain ---
open(LOG, 'w').close()
print("  Test 3: c19.com (19-level CNAME chain)")
print("    Sending ns1.c19.com A query...")
rcode, ms, ans = dns_query("ns1.c19.com", QT_A, timeout=30)
time.sleep(1)
chain_q = [json.loads(l) for l in open(LOG) if l.strip()]
print(f"    ns1.c19.com A: {rcode} {ms:.1f}ms, auth queries: {len(chain_q)}")

# --- Test 4: Query each CNAME level directly ---
print()
print("  Test 4: Direct CNAME level queries (each level individually)")
for level in [18, 15, 10, 5, 1, 0]:
    name = f"c{level}.c19.com"
    open(LOG, 'w').close()
    rcode, ms2, ans2 = dns_query(name, QT_A, timeout=10)
    time.sleep(0.5)
    level_q = [json.loads(l) for l in open(LOG) if l.strip()]
    print(f"    {name} A: {rcode} {ms2:.1f}ms, auth queries: {len(level_q)}")

# --- Analyze 19-level chain query log ---
print()
print("  ═════════════════════════════════════════════════════════")
print("  DETAILED ANALYSIS: 19-level CNAME chain")
print("  ═════════════════════════════════════════════════════════")
print()

if not chain_q:
    print("  NO queries received by auth server for ns1.c19.com!")
    print("  Unbound may have cached the SERVFAIL from a previous run.")
else:
    print(f"  Total queries from Unbound: {len(chain_q)}")
    print()
    print(f"  {'#':>3} | {'Query Name':<25} | {'Type':<7} | {'RelTime(ms)':>11} | {'Delta(ms)':>9}")
    print("  " + "-" * 70)
    prev_ts = 0
    for i, q in enumerate(chain_q):
        delta = q['ts'] - prev_ts if i > 0 else 0
        prev_ts = q['ts']
        print(f"  {i+1:3d} | {q['qname']:<25} | {q['qtype']:<7} | {q['ts']:>11.1f} | {delta:>9.1f}")

    # Identify CNAME levels resolved
    levels_resolved = set()
    for q in chain_q:
        n = q['qname'].lower()
        if n == 'ns1.c19.com':
            levels_resolved.add(19)
        elif n.endswith('.c19.com'):
            prefix = n.split('.')[0]
            if prefix.startswith('c'):
                try:
                    levels_resolved.add(int(prefix[1:]))
                except ValueError:
                    pass

    all_levels = set(range(0, 19)) | {19}  # 19=ns1, 18..0=c18..c0
    missing = all_levels - levels_resolved

    print()
    print(f"  CNAME levels resolved by Unbound: {sorted(levels_resolved)}")
    if missing:
        print(f"  CNAME levels MISSING:            {sorted(missing)}")
    else:
        print(f"  All 19 CNAME levels + terminal A were queried!")
    print(f"  Depth reached: {max(levels_resolved) if levels_resolved else 'none'}")
    print(f"  Chain completeness: {len(levels_resolved - {19})}/19 CNAME levels")

    total_auth_time = chain_q[-1]['ts'] - chain_q[0]['ts'] if len(chain_q) > 1 else 0
    print(f"  Total auth resolution window: {total_auth_time:.1f}ms")

    if missing:
        print()
        deepest = max(levels_resolved - {19}) if (levels_resolved - {19}) else -1
        print(f"  ⚠ Unbound STOPPED at c{deepest}.c19.com (level {deepest})")
        print(f"  It did NOT reach c0.c19.com (level 0, the terminal A record)")
        print()
        if rcode == 'SERVFAIL':
            print(f"  → Returned SERVFAIL after resolving {len(levels_resolved)} levels")
            print(f"  → The {ms:.1f}ms total time includes resolution of {len(levels_resolved)} levels")
            print(f"     + retry/wait logic for the remaining {len(missing)} levels")
        else:
            print(f"  → Returned {rcode} — unexpected for incomplete chain")
    else:
        print()
        print(f"  ✓ Unbound fully traced all 19 CNAME levels")
        print(f"  Total time: {ms:.1f}ms")

    # Timing analysis
    print()
    print("  ─── Timing per query ───")
    if len(chain_q) > 1:
        deltas = [chain_q[i]['ts'] - chain_q[i-1]['ts'] for i in range(1, len(chain_q))]
        avg_delta = sum(deltas) / len(deltas)
        max_delta = max(deltas)
        slow_queries = [(i+1, chain_q[i+1], d) for i, d in enumerate(deltas) if d > avg_delta * 3]
        print(f"  Average inter-query time: {avg_delta:.1f}ms")
        print(f"  Max inter-query time: {max_delta:.1f}ms")
        if slow_queries:
            print(f"  Slow queries (>3x average):")
            for idx, q, d in slow_queries[:5]:
                print(f"    Query #{idx}: {q['qname']} {q['qtype']} — {d:.1f}ms gap")

# --- Amplification ---
print()
print("  ─── Amplification Factor ───")
if direct_q and chain_q:
    direct_time = direct_q[-1]['ts'] - direct_q[0]['ts'] if len(direct_q) > 1 else 1
    chain_time = chain_q[-1]['ts'] - chain_q[0]['ts'] if len(chain_q) > 1 else ms
    print(f"  direct.com auth time: {direct_time:.1f}ms ({len(direct_q)} queries)")
    print(f"  c19.com auth time:    {chain_time:.1f}ms ({len(chain_q)} queries)")
    if direct_time > 0:
        print(f"  Amplification: {chain_time/direct_time:.1f}x")
    print(f"  Query count ratio: {len(chain_q)}/{len(direct_q)} = {len(chain_q)/max(len(direct_q),1):.1f}x")

# --- Caching test ---
print()
print("  ─── Caching Test (repeat ns1.c19.com A) ───")
open(LOG, 'w').close()
rcode2, ms2, ans2 = dns_query("ns1.c19.com", QT_A, timeout=10)
time.sleep(0.5)
cache_q = [json.loads(l) for l in open(LOG) if l.strip()]
print(f"  Repeat: {rcode2} {ms2:.1f}ms, auth queries: {len(cache_q)}")
if len(cache_q) == 0:
    print("  ✓ Fully cached (0 auth queries)")
elif len(cache_q) < len(chain_q):
    print(f"  Partial cache: {len(cache_q)}/{len(chain_q)} queries still sent")
else:
    print(f"  No cache benefit: all {len(cache_q)} queries re-sent")

PYEOF

# ═══ Step 4: Unbound source code limit check ═══
echo ""
echo "═══ Step 4: Unbound CNAME chain limit in source ═══"

# Check Unbound's max CNAME chain depth
echo "  Searching Unbound source for CNAME chain limits..."
grep -rn "MAX_CNAME\|max_cname\|CNAME.*limit\|CNAME.*depth\|MAX_CHAIN\|cname_count\|cname_chase\|minimise" \
  /workspace/output/unbound-source/iterator/ /workspace/output/unbound-source/services/ \
  2>/dev/null | head -20

echo ""
echo "  Searching for max_queries_per_response or similar limits..."
grep -rn "max_query\|MAX_COUNT\|target_count\|MAX_TARGET\|query_count\|max_count" \
  /workspace/output/unbound-source/iterator/ 2>/dev/null | head -20

# ═══ Step 5: Unbound log ═══
echo ""
echo "═══ Step 5: Unbound log ═══"

echo ""
echo "  --- c19.com entries ---"
grep -i "c19\.com" "$VDIR/unbound.log" 2>/dev/null | head -60 || echo "  (none)"

echo ""
echo "  --- CNAME/limit related ---"
grep -i "cname\|chain\|depth\|limit\|maximum\|too.*many\|loop\|cycle" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

# ═══ Health ═══
echo ""
echo "═══ Health ═══"
kill -0 "$UB_PID" 2>/dev/null && echo "  Unbound: ALIVE" || echo "  Unbound: DEAD"
if kill -0 "$UB_PID" 2>/dev/null; then
  ps -o pid,rss,vsz,comm -p "$UB_PID" 2>/dev/null || true
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Summary                                                ║"
echo "╚══════════════════════════════════════════════════════════╝"

kill_all
kill "$AUTH_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
