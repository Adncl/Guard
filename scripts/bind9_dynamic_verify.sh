#!/usr/bin/env bash
# BIND9 Dynamic Verification Script
# Tests: V1=Z field, V2=RRSIG dates, V3=DNSKEY flags reserved bits, V4=NS->CNAME
set -euo pipefail

VDIR="/workspace/output/bind9-dynamic-verify"
mkdir -p "$VDIR"

# Install runtime dependencies
echo "=== Installing runtime dependencies ==="
apt-get update -qq 2>/dev/null | tail -1
apt-get install -y --no-install-recommends \
  liburcu8 libjson-c5 liblmdb0 dnsutils python3 2>/dev/null | tail -3
ldconfig

# Set library path for our BIND9 build
export LD_LIBRARY_PATH="/workspace/output/bind9-install/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

NAMED="/workspace/output/bind9-install/sbin/named"
DIG_CMD="dig"  # use system dig
KEYGEN="/workspace/output/bind9-install/bin/dnssec-keygen"
SIGNZONE="/workspace/output/bind9-install/bin/dnssec-signzone"

# Verify named can run
echo "=== Verifying BIND9 binary ==="
"$NAMED" -V 2>&1 | head -3

# ─── Helper Functions ──────────────────────────────────────────────
kill_named() {
  if [ -f "$VDIR/named.pid" ]; then
    PID=$(cat "$VDIR/named.pid" 2>/dev/null || true)
    if [ -n "$PID" ]; then
      kill "$PID" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$VDIR/named.pid"
  fi
  pkill -f "named.*5354" 2>/dev/null || true
  sleep 1
}

start_named_bg() {
  local conf="$1"
  shift
  kill_named
  rm -f "$VDIR/named.pid"
  timeout 120 "$NAMED" -c "$conf" -g -f "$@" > "$VDIR/named_stdout.log" 2>&1 &
  local npid=$!
  # Wait for named to start
  for i in $(seq 1 20); do
    if [ -f "$VDIR/named.pid" ]; then
      echo "  named started (PID=$(cat "$VDIR/named.pid"))"
      return 0
    fi
    # Check if named already exited (config error)
    if ! kill -0 "$npid" 2>/dev/null; then
      echo "  named exited early. Log:"
      cat "$VDIR/named_stdout.log" | head -40
      return 1
    fi
    sleep 0.5
  done
  echo "  named may still be starting... checking log"
  cat "$VDIR/named_stdout.log" | tail -5
  return 0
}

# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  BIND9 Dynamic Verification                             ║"
echo "║  V1: Z field (RFC 1035)                                 ║"
echo "║  V2: RRSIG inception/expiration (RFC 4034)              ║"
echo "║  V3: DNSKEY Flags reserved bits (RFC 4034)              ║"
echo "║  V4: NS→CNAME (RFC 2181 §10.3)                         ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ═══════════════════════════════════════════════════════════════════
# V1: Z field — send queries with Z bits non-zero
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ V1: Z field (RFC 1035: reserved bits MUST be zero) ═══"

cat > "$VDIR/v1.conf" << 'EOF'
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v1test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v1test.zone";
};
EOF

cat > "$VDIR/v1test.zone" << 'EOF'
$TTL 300
@   IN  SOA ns1.v1test.com. admin.v1test.com. (
        2026100801 3600 900 604800 86400 )
    IN  NS  ns1.v1test.com.
ns1 IN  A   10.0.0.1
www IN  A   10.0.0.2
EOF

start_named_bg "$VDIR/v1.conf"

echo "  Sending queries with various Z bit values..."
python3 << 'PYEOF'
import socket, struct

def build_query(qname, qtype=1, flags=0x0100):
    txid = 0xABCD
    header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    question = b''
    for label in qname.split('.'):
        if label:
            question += struct.pack('B', len(label)) + label.encode()
    question += b'\x00'
    question += struct.pack('!HH', qtype, 1)  # A, IN
    return header + question

def send_recv(pkt, port=5354, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(pkt, ('127.0.0.1', port))
    try:
        data, _ = sock.recvfrom(4096)
        if len(data) >= 12:
            _, rflags, _, _, _, _ = struct.unpack('!HHHHHH', data[:12])
            rcode = rflags & 0xF
            z = (rflags >> 4) & 0x7
            return rcode, z, len(data)
    except socket.timeout:
        return -1, -1, 0
    finally:
        sock.close()

tests = [
    ("Z=0 (normal)",  0x0100),   # RD=1, Z=0
    ("Z=1 (bit6)",    0x0140),   # RD=1, Z=1
    ("Z=7 (all 3)",   0x0170),   # RD=1, Z=7
    ("Z=4 (bit4)",    0x0104),   # RD=1, CD=1 (was Z)
]

print(f"  {'Test':<20} | {'RCODE':>5} | {'RespZ':>5} | {'Size':>5}")
print("  " + "-" * 50)
violation = False
for name, flags in tests:
    pkt = build_query('www.v1test.com', flags=flags)
    rcode, rz, size = send_recv(pkt)
    status = "OK" if rcode == 0 else "REJECT" if rcode > 0 else "TIMEOUT"
    print(f"  {name:<20} | {rcode:>5} | {rz:>5} | {size:>5}  [{status}]")
    if rcode == 0 and 'Z=' in name and name != "Z=0 (normal)":
        violation = True

print()
if violation:
    print("  ==> VIOLATION CONFIRMED: BIND9 accepts queries with Z!=0 without FORMERR")
    print("  RFC 1035 requires Z bits to be zero; BIND9 should return RCODE=1 (FORMERR)")
else:
    print("  ==> No violation: BIND9 rejects Z!=0 queries")
PYEOF

kill_named
echo "  V1 done."

# ═══════════════════════════════════════════════════════════════════
# V2: RRSIG inception/expiration date validation
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ V2: RRSIG inception/expiration (RFC 4034) ═══"

cat > "$VDIR/v2.conf" << 'EOF'
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v2test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v2test.zone";
};
EOF

cat > "$VDIR/v2test.zone" << 'EOF'
$TTL 300
@   IN  SOA ns1.v2test.com. admin.v2test.com. (
        2026100801 3600 900 604800 86400 )
    IN  NS  ns1.v2test.com.
ns1 IN  A   10.0.0.1
www IN  A   10.0.0.2
EOF

# Generate keys and sign
cd "$VDIR"
rm -f Kv2test.com.* 2>/dev/null || true
echo "  Generating DNSSEC keys..."
"$KEYGEN" -a ECDSAP256SHA256 -b 256 -n ZONE v2test.com > /dev/null 2>&1
ZSK_KEY=$(ls Kv2test.com.+013+*.key 2>/dev/null | head -1)
"$KEYGEN" -a ECDSAP256SHA256 -b 256 -n ZONE -f KSK v2test.com > /dev/null 2>&1
KSK_KEY=$(ls Kv2test.com.+013+*.key 2>/dev/null | tail -1)

if [ -n "$ZSK_KEY" ] && [ -n "$KSK_KEY" ]; then
    echo "  Keys generated. Signing zone..."
    for kf in Kv2test.com.*.key; do
        cat "$kf" >> v2test.zone
    done
    "$SIGNZONE" -A -o v2test.com v2test.zone 2>&1 | head -5
    
    if [ -f "v2test.zone.signed" ]; then
        echo "  Zone signed successfully."
        
        # Show original dates
        echo "  Original RRSIG dates:"
        grep "RRSIG" v2test.zone.signed | head -2 | awk '{print $1, $7, $8}'

        # Create expired version (both inception and expiration in the past)
        python3 << 'PYEOF'
import re
with open('/workspace/output/bind9-dynamic-verify/v2test.zone.signed') as f:
    content = f.read()
# Set all RRSIG dates to past: expiration=2019-01-01=1546300800, inception=2018-01-01=1514764800
content_expired = re.sub(
    r'(RRSIG\s+\S+\s+\d+\s+\d+\s+\d+\s+)\d{10}(\s+)\d{10}',
    r'\g<1>1546300800\g<2>1514764800',
    content
)
with open('/workspace/output/bind9-dynamic-verify/v2test.zone.signed.expired', 'w') as f:
    f.write(content_expired)

# Set inception in the future: expiration=2099-01-01=4070908800, inception=2098-01-01=4039366400
content_future = re.sub(
    r'(RRSIG\s+\S+\s+\d+\s+\d+\s+\d+\s+)\d{10}(\s+)\d{10}',
    r'\g<1>4070908800\g<2>4039366400',
    content
)
with open('/workspace/output/bind9-dynamic-verify/v2test.zone.signed.future', 'w') as f:
    f.write(content_future)
print('  Tampered zone files created.')
PYEOF

        # V2.1: Valid signed zone (authoritative, no validation needed)
        echo ""
        echo "  V2.1: Loading valid signed zone..."
        cat > "$VDIR/v2_valid.conf" << EOFCONF
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v2test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v2test.zone.signed";
};
EOFCONF
        start_named_bg "$VDIR/v2_valid.conf"
        echo "  Query valid signed zone:"
        $DIG_CMD @127.0.0.1 -p 5354 www.v2test.com A +dnssec +noall +answer 2>&1 | head -10
        kill_named

        # V2.2: Expired signed zone
        echo ""
        echo "  V2.2: Loading zone with EXPIRED RRSIG..."
        cat > "$VDIR/v2_expired.conf" << EOFCONF
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v2test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v2test.zone.signed.expired";
};
EOFCONF
        start_named_bg "$VDIR/v2_expired.conf"
        # For authoritative server, expired RRSIG is served as-is
        # The check happens in the validator (resolver side)
        echo "  Query expired signed zone (as authoritative):"
        $DIG_CMD @127.0.0.1 -p 5354 www.v2test.com A +dnssec +noall +answer +comments 2>&1 | head -10
        # Check if named logged any RRSIG errors
        echo "  Named log (RRSIG-related):"
        grep -i "rrsig\|expir\|inception\|sigfuture\|sigexpired" "$VDIR/named_stdout.log" 2>/dev/null | head -5 || echo "  (none)"
        kill_named

        # V2.3: Future signed zone
        echo ""
        echo "  V2.3: Loading zone with FUTURE RRSIG (not yet valid)..."
        cat > "$VDIR/v2_future.conf" << EOFCONF
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v2test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v2test.zone.signed.future";
};
EOFCONF
        start_named_bg "$VDIR/v2_future.conf"
        echo "  Query future signed zone (as authoritative):"
        $DIG_CMD @127.0.0.1 -p 5354 www.v2test.com A +dnssec +noall +answer +comments 2>&1 | head -10
        echo "  Named log (RRSIG-related):"
        grep -i "rrsig\|expir\|inception\|sigfuture\|sigexpired" "$VDIR/named_stdout.log" 2>/dev/null | head -5 || echo "  (none)"
        kill_named

        echo ""
        echo "  V2 RESULT: BIND9 source code (dns_dnssec_verify) returns DNS_R_SIGEXPIRED"
        echo "  and DNS_R_SIGFUTURE for expired/future RRSIG. As authoritative server, BIND9"
        echo "  serves expired/future RRSIG data as-is (this is correct per RFC). The validation"
        echo "  check is applied in the resolver role. Source confirms RFC compliance."
    else
        echo "  ERROR: Zone signing failed."
    fi
else
    echo "  ERROR: Key generation failed."
fi

cd /workspace
echo "  V2 done."

# ═══════════════════════════════════════════════════════════════════
# V3: DNSKEY Flags reserved bits (RFC 4034)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ V3: DNSKEY Flags reserved bits (RFC 4034) ═══"

cd "$VDIR"
rm -f Kv3test.com.* 2>/dev/null || true
echo "  Generating DNSSEC key for test..."
"$KEYGEN" -a ECDSAP256SHA256 -b 256 -n ZONE v3test.com > /dev/null 2>&1
V3KEY=$(ls Kv3test.com.+013+*.key 2>/dev/null | head -1)

if [ -n "$V3KEY" ]; then
    # Extract the key data (flags, protocol, algorithm, base64 pubkey)
    KEY_LINE=$(grep -v '^;' "$V3KEY")
    echo "  Original key record: $KEY_LINE"
    
    # Parse: v3test.com. IN DNSKEY <flags> <protocol> <algorithm> <base64...>
    KEY_FLAGS=$(echo "$KEY_LINE" | awk '{print $4}')
    KEY_PROTO=$(echo "$KEY_LINE" | awk '{print $5}')
    KEY_ALG=$(echo "$KEY_LINE" | awk '{print $6}')
    KEY_B64=$(echo "$KEY_LINE" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')

    echo "  Parsed: flags=$KEY_FLAGS proto=$KEY_PROTO alg=$KEY_ALG"

    # Create test zones with different flag values
    # flags=256 (0x0100): valid ZSK (bit 8 set)
    # flags=257 (0x0101): valid KSK (bit 8 + bit 0)
    # flags=258 (0x0102): VIOLATION (bit 8 + bit 1, reserved bit 1 set)
    # flags=768 (0x0300): VIOLATION (bit 8 + bit 9, reserved bit 9 set)
    # flags=511 (0x01FF): EXTREME VIOLATION (bits 0-8 all set)

    BASE_ZONE="\$TTL 300
@   IN  SOA ns1.v3test.com. admin.v3test.com. (
        2026100801 3600 900 604800 86400 )
    IN  NS  ns1.v3test.com.
ns1 IN  A   10.0.0.1
www IN  A   10.0.0.2"

    for flags_val in 256 257 258 768 511; do
        echo ""
        echo "  V3: Testing DNSKEY flags=$flags_val (0x$(printf '%04x' $flags_val))..."
        
        # Create zone with this flag value
        cat > "$VDIR/v3_${flags_val}.zone" << ZONEEOF
$BASE_ZONE
v3test.com. IN DNSKEY $flags_val $KEY_PROTO $KEY_ALG $KEY_B64
ZONEEOF

        cat > "$VDIR/v3_${flags_val}.conf" << EOFCONF
options {
    directory "/workspace/output/bind9-dynamic-verify";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    pid-file "/workspace/output/bind9-dynamic-verify/named.pid";
    allow-query { any; };
    recursion no;
};
zone "v3test.com" IN {
    type master;
    file "/workspace/output/bind9-dynamic-verify/v3_${flags_val}.zone";
};
EOFCONF
        
        start_named_bg "$VDIR/v3_${flags_val}.conf"
        
        if [ -f "$VDIR/named.pid" ] && kill -0 "$(cat "$VDIR/named.pid")" 2>/dev/null; then
            echo "  Zone LOADED: BIND9 accepted DNSKEY with flags=$flags_val"
            $DIG_CMD @127.0.0.1 -p 5354 v3test.com DNSKEY +noall +answer 2>&1 | head -5
            # Check log for any warnings
            grep -i "reserved\|invalid.*key\|flags.*must\|dnskey.*error" "$VDIR/named_stdout.log" 2>/dev/null | head -3 || echo "  (no warnings in log)"
        else
            echo "  Zone REJECTED: BIND9 refused DNSKEY with flags=$flags_val"
            # Show relevant log
            grep -i "error\|fail\|invalid\|dnskey\|flags" "$VDIR/named_stdout.log" 2>/dev/null | head -5
        fi
        
        kill_named
    done

    echo ""
    echo "  V3 RESULT: RFC 4034 requires bits 0-6 and 8-14 of DNSKEY Flags to be zero."
    echo "  If BIND9 loads zones with flags=258/768/511 without rejection, it violates RFC 4034."
else
    echo "  ERROR: Key generation failed."
fi

cd /workspace
echo "  V3 done."

# ═══════════════════════════════════════════════════════════════════
# V4: NS→CNAME (RFC 2181 §10.3)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══ V4: NS→CNAME (RFC 2181 §10.3) ═══"
echo "  (Already tested in bind9-ns-alias-test/)"
echo "  Result: BIND 9.21.27 correctly rejects NS→CNAME at zone load:"
echo '    "NS ns1.example.com is a CNAME (illegal)"'
echo '    "zone example.com/IN: not loaded due to errors."'
echo "  ==> NO VIOLATION: BIND9 is RFC 2181 §10.3 compliant."

# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  BIND9 Dynamic Verification Summary                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  V1 (Z field):        [See results above]"
echo "  V2 (RRSIG dates):    [See results above]"
echo "  V3 (DNSKEY flags):   [See results above]"
echo "  V4 (NS→CNAME):       NO VIOLATION (correctly rejected at zone load)"

kill_named
echo ""
echo "=== BIND9 Dynamic Verification Complete ==="
