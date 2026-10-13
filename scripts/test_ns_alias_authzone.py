"""Targeted wire-level test for the RFC 2181 10.3 (NS target MUST NOT be an alias) finding.

The static detection flagged az_insert_rr (services/authzone.c) for accepting an
NS record whose target is a CNAME alias. This script loads a local auth-zone
whose NS target is a CNAME, then queries Unbound over TCP and reports whether
the aliased NS is served (violation) or rejected (compliant). Fully offline.
"""
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'output' / 'unbound-binary-baseline'
WORK = ROOT / 'output' / 'ns-alias-test'
WORK.mkdir(parents=True, exist_ok=True)

zonefile = WORK / 'example.com.zone'
zonefile.write_text(
    '$ORIGIN example.com.\n'
    '$TTL 3600\n'
    '@   IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 1200 604800 3600 )\n'
    '@   IN NS  ns1.example.com.\n'
    'ns1 IN CNAME real.example.com.\n'
    'real IN A 192.0.2.1\n')

with socket.socket() as reserved:
    reserved.bind(('127.0.0.1', 0))
    port = reserved.getsockname()[1]

conf = WORK / 'unbound.conf'
conf.write_text(
    'server:\n'
    f'  interface: 127.0.0.1@{port}\n'
    '  do-daemonize: no\n'
    '  username: ""\n'
    '  chroot: ""\n'
    '  directory: ""\n'
    '  pidfile: ""\n'
    '  logfile: ""\n'
    '  use-syslog: no\n'
    '  do-udp: no\n'
    '  do-tcp: yes\n'
    '  do-ip6: no\n'
    '  verbosity: 0\n'
    '  access-control: 127.0.0.0/8 allow\n'
    '  module-config: "validator iterator"\n'
    'auth-zone:\n'
    '  name: "example.com."\n'
    f'  zonefile: "{zonefile}"\n'
    '  fallback-enabled: no\n')


def query(qname, qtype):
    header = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
    msg = header + qname + struct.pack('>HH', qtype, 1)
    return struct.pack('>H', len(msg)) + msg


def run_query(payload):
    stdout = WORK / 'srv.stdout'
    stderr = WORK / 'srv.stderr'
    with stdout.open('wb') as out, stderr.open('wb') as err:
        proc = subprocess.Popen([str(BINARY), '-c', str(conf)], stdout=out, stderr=err,
                                cwd=WORK, start_new_session=True)
        connected = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                sock = socket.create_connection(('127.0.0.1', port), timeout=0.1)
                connected = True
                break
            except OSError:
                time.sleep(0.02)
        if not connected:
            return None, stderr.read_text(errors='replace')
        response = b''
        with sock:
            sock.settimeout(1.0)
            sock.sendall(payload)
            while True:
                try:
                    block = sock.recv(65535)
                    if not block:
                        break
                    response += block
                except (socket.timeout, ConnectionResetError):
                    break
        time.sleep(0.1)
        if proc.poll() is None:
            import os
            import signal
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
    return response, stderr.read_text(errors='replace')


def parse(response):
    if len(response) < 14:
        return None
    length = struct.unpack('>H', response[:2])[0]
    msg = response[2:2 + length]
    if len(msg) < 12:
        return None
    flags = struct.unpack('>H', msg[2:4])[0]
    rcode = flags & 0xF
    qr = (flags >> 15) & 1
    qd = struct.unpack('>H', msg[4:6])[0]
    an = struct.unpack('>H', msg[6:8])[0]
    return {'qr': qr, 'rcode': rcode, 'qd': qd, 'an': an}


ns_payload = query(b'\x07example\x03com\x00', 2)       # NS
a_payload = query(b'\x03ns1\x07example\x03com\x00', 1)  # A (to the alias)
results = {}
for label, payload in [('NS example.com', ns_payload), ('A ns1.example.com', a_payload)]:
    resp, err = run_query(payload)
    results[label] = {'raw': resp.hex() if resp else '', 'parsed': parse(resp) if resp else None,
                      'server_stderr_tail': (err or '')[-300:]}
    print(f'=== {label} ===')
    print('  response:', resp.hex() if resp else '(none)')
    print('  parsed:', parse(resp) if resp else None)

# Decision
ns = results['NS example.com']['parsed']
a = results['A ns1.example.com']['parsed']
served_aliased_ns = (ns is not None and ns['rcode'] == 0 and ns['an'] >= 1 and
                     a is not None and a['rcode'] == 0 and a['an'] >= 1)
verdict = ('VIOLATION CONFIRMED: Unbound serves an NS record whose target is a CNAME alias'
           if served_aliased_ns else
           'NOT CONFIRMED: Unbound rejected or did not serve the aliased NS record')
print('\n' + '=' * 70)
print(verdict)
print('=' * 70)
