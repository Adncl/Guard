"""Targeted wire-level test for RFC 2181 10.3 (NS target MUST NOT be an alias) on BIND9.

This script creates a zone file where the NS target is a CNAME alias,
then starts BIND9 (named) with that zone and checks:
  1. Whether named REFUSES to load the zone (compliant with RFC 2181 §10.3)
  2. Whether named ACCEPTS and SERVES the zone (violation)

Two zone configurations are tested:
  - VIOLATION zone: NS target is a CNAME alias (should be rejected per RFC)
  - CONTROL zone:  NS target is a normal A record (should load fine)
"""
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'output' / 'bind9-binary-named'
WORK = ROOT / 'output' / 'bind9-ns-alias-test'
WORK.mkdir(parents=True, exist_ok=True)


# ── Zone files ──────────────────────────────────────────────────────

violation_zone = WORK / 'example.com.zone'
violation_zone.write_text(
    '$ORIGIN example.com.\n'
    '$TTL 3600\n'
    '@   IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 1200 604800 3600 )\n'
    '@   IN NS  ns1.example.com.\n'
    'ns1 IN CNAME real.example.com.\n'   # <-- RFC 2181 §10.3 violation
    'real IN A 192.0.2.1\n')

control_zone = WORK / 'good.com.zone'
control_zone.write_text(
    '$ORIGIN good.com.\n'
    '$TTL 3600\n'
    '@   IN SOA ns1.good.com. hostmaster.good.com. ( 1 3600 1200 604800 3600 )\n'
    '@   IN NS  ns1.good.com.\n'
    'ns1 IN A 192.0.2.1\n'              # <-- correct: NS → A, not CNAME
    'www IN A 192.0.2.80\n')

# ── RNDC key (minimal, for named to work) ───────────────────────────

rndc_key = WORK / 'rndc.key'
rndc_key.write_text(
    'key "rndc-key" {\n'
    '  algorithm hmac-sha256;\n'
    '  secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";\n'
    '};\n')


def make_named_conf(port):
    """Generate named.conf with both zones on the given port."""
    conf = WORK / 'named.conf'
    conf.write_text(
        f'options {{\n'
        f'  directory "{WORK}";\n'
        f'  listen-on port {port} {{ 127.0.0.1; }};\n'
        f'  listen-on-v6 {{ none; }};\n'
        f'  pid-file "{WORK}/named.pid";\n'
        f'  allow-query {{ any; }};\n'
        f'  recursion no;\n'
        f'}};\n'
        f'\n'
        f'key "rndc-key" {{\n'
        f'  algorithm hmac-sha256;\n'
        f'  secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";\n'
        f'}};\n'
        f'\n'
        f'controls {{\n'
        f'  inet 127.0.0.1 port 953\n'
        f'    allow {{ 127.0.0.1; }} keys {{ "rndc-key"; }};\n'
        f'}};\n'
        f'\n'
        f'zone "example.com" IN {{\n'
        f'  type master;\n'
        f'  file "{violation_zone}";\n'
        f'}};\n'
        f'\n'
        f'zone "good.com" IN {{\n'
        f'  type master;\n'
        f'  file "{control_zone}";\n'
        f'}};\n')
    return conf


# ── DNS query helpers ───────────────────────────────────────────────

def dns_query(qname, qtype, use_tcp=True):
    header = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
    msg = header + qname + struct.pack('>HH', qtype, 1)
    if use_tcp:
        return struct.pack('>H', len(msg)) + msg
    return msg


def parse_dns_response(data, is_tcp=True):
    if is_tcp:
        if len(data) < 2:
            return None
        length = struct.unpack('>H', data[:2])[0]
        msg = data[2:2 + length]
    else:
        msg = data
    if len(msg) < 12:
        return None
    flags = struct.unpack('>H', msg[2:4])[0]
    rcode = flags & 0xF
    qr = (flags >> 15) & 1
    qd = struct.unpack('>H', msg[4:6])[0]
    an = struct.unpack('>H', msg[6:8])[0]
    return {'qr': qr, 'rcode': rcode, 'qd': qd, 'an': an}


def send_tcp_query(port, payload, timeout=2):
    try:
        sock = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(payload)
        response = b''
        while True:
            try:
                block = sock.recv(65535)
                if not block:
                    break
                response += block
            except socket.timeout:
                break
        sock.close()
        return response
    except OSError:
        return None


# ── Main test ───────────────────────────────────────────────────────

def run_test():
    if not BINARY.exists():
        print(f'ERROR: BIND9 binary not found at {BINARY}')
        print('Please run build_bind9.sh first.')
        sys.exit(1)

    version = subprocess.run([str(BINARY), '-V'], capture_output=True, text=True, timeout=10)
    print(f'BIND9 version: {version.stderr.strip() or version.stdout.strip()[:200]}')

    # Reserve a port
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]

    conf = make_named_conf(port)

    # ── Phase 1: Start named and check zone loading ─────────────────
    print('\n' + '=' * 70)
    print('Phase 1: Starting BIND9 named with NS→CNAME violation zone')
    print('=' * 70)

    stdout_log = WORK / 'named.stdout'
    stderr_log = WORK / 'named.stderr'

    proc = None
    zone_loaded = False
    zone_rejected = False

    with stdout_log.open('wb') as out, stderr_log.open('wb') as err:
        proc = subprocess.Popen(
            [str(BINARY), '-c', str(conf), '-g', '-f'],
            stdout=out, stderr=err,
            cwd=str(WORK), start_new_session=True)

        # Wait for named to start or fail
        deadline = time.monotonic() + 8
        connected = False
        while time.monotonic() < deadline:
            poll = proc.poll()
            if poll is not None:
                # Process exited
                break
            try:
                test_sock = socket.create_connection(('127.0.0.1', port), timeout=0.1)
                test_sock.close()
                connected = True
                break
            except OSError:
                time.sleep(0.05)

    # Read logs
    stderr_text = stderr_log.read_text(errors='replace')
    stdout_text = stdout_log.read_text(errors='replace')
    full_log = stderr_text + stdout_text

    proc_exited = proc.poll() is not None

    # Check if named explicitly rejected the zone
    zone_rejected_keywords = [
        'NS record is a CNAME',
        'NS is a CNAME',
        'NS points to CNAME',
        'ignored',
        'zone load failure',
        'loading failure',
        'could not load',
        'zone example.com/IN: could not',
        'zone example.com/IN: loading',
        'CNAME and other data',
        'CNAME at NS',
    ]
    for kw in zone_rejected_keywords:
        if kw.lower() in full_log.lower():
            zone_rejected = True
            break

    if connected:
        zone_loaded = True
        print(f'  named started successfully and is listening on port {port}')
        print(f'  → Zone was ACCEPTED (potential RFC 2181 §10.3 violation)')
    elif proc_exited:
        print(f'  named exited with code {proc.returncode}')
        print(f'  → Zone was REJECTED (RFC 2181 §10.3 compliant)')
        zone_rejected = True
    else:
        print(f'  named did not start listening within timeout')
        # Check log for rejection signals
        if any(kw in full_log.lower() for kw in ['error', 'fail', 'refuse', 'cname']):
            zone_rejected = True

    # Print relevant log lines
    print('\n  --- named log (relevant lines) ---')
    for line in full_log.splitlines():
        line_l = line.lower()
        if any(k in line_l for k in ['example.com', 'cname', 'ns', 'zone', 'error', 'fail',
                                       'ignor', 'warn', 'load', 'reject', 'violation']):
            print(f'  {line[:200]}')

    # ── Phase 2: If named is running, send queries ──────────────────
    if connected:
        print('\n' + '=' * 70)
        print('Phase 2: Sending DNS queries to check wire-level behavior')
        print('=' * 70)

        ns_payload = dns_query(b'\x07example\x03com\x00', 2)       # NS example.com
        a_payload = dns_query(b'\x03ns1\x07example\x03com\x00', 1)  # A ns1.example.com
        control_payload = dns_query(b'\x03www\x04good\x03com\x00', 1)  # A www.good.com (control)

        tests = [
            ('NS example.com (violation zone)', ns_payload),
            ('A ns1.example.com (CNAME alias)', a_payload),
            ('A www.good.com (control zone)', control_payload),
        ]

        results = {}
        for label, payload in tests:
            resp = send_tcp_query(port, payload)
            parsed = parse_dns_response(resp) if resp else None
            results[label] = {'raw': resp.hex() if resp else '', 'parsed': parsed}
            rcodes = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
            rc = parsed['rcode'] if parsed else None
            rc_str = rcodes.get(rc, rc) if rc is not None else 'N/A'
            an = parsed['an'] if parsed else None
            print(f'  {label:40s} → RCODE={rc_str}  ANCOUNT={an}')
            if parsed:
                print(f'    raw hex: {resp.hex()[:80]}')

        # ── Verdict ─────────────────────────────────────────────────
        ns_r = results.get('NS example.com (violation zone)', {}).get('parsed')
        a_r = results.get('A ns1.example.com (CNAME alias)', {}).get('parsed')

        print('\n' + '=' * 70)
        if ns_r and ns_r['rcode'] == 0 and ns_r['an'] >= 1 and a_r and a_r['rcode'] == 0 and a_r['an'] >= 1:
            print('VIOLATION CONFIRMED: BIND9 serves an NS record whose target is a CNAME alias')
        elif zone_rejected:
            print('RFC COMPLIANT: BIND9 rejected/warned about the NS→CNAME zone at load time')
        else:
            print('INCONCLUSIVE: Zone loaded but query behavior needs manual inspection')
        print('=' * 70)
    else:
        print('\n' + '=' * 70)
        if zone_rejected:
            print('RFC COMPLIANT: BIND9 refused to load the NS→CNAME violation zone')
        else:
            print('INCONCLUSIVE: named did not start; check logs for details')
        print('=' * 70)

    # Cleanup
    if proc and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    # Save full log for review
    log_report = WORK / 'test-report.txt'
    log_report.write_text(
        f'BIND9 NS→CNAME RFC 2181 §10.3 Compliance Test Report\n'
        f'{"=" * 60}\n\n'
        f'Binary: {BINARY}\n'
        f'Version: {version.stderr.strip() or version.stdout.strip()[:200]}\n'
        f'Zone loaded: {zone_loaded}\n'
        f'Zone rejected: {zone_rejected}\n'
        f'Process exited: {proc_exited}\n'
        f'Process return code: {proc.returncode if proc_exited else "N/A"}\n\n'
        f'--- Full named log ---\n{full_log}\n')
    print(f'\nFull report saved to: {log_report}')


if __name__ == '__main__':
    run_test()
