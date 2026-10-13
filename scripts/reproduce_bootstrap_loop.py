"""Reproduce the RFC 2181 10.3 bootstrap deadlock on Unbound 1.26.0.

Two Unbound instances:
  A (authoritative)  : auth-zones example.com / example.net (NS target is an
                       alias -> cross-zone CNAME chain) and a correct control
                       zone good.com.
  B (recursive)      : stub-zones pointing at A; follows the delegation.

Querying B for the NS target shows the resolver unable to bootstrap the
nameserver address (CNAME chain cannot terminate -> SERVFAIL with a loop
trace), while the correct control zone resolves normally.
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
BINARY = ROOT / 'output' / 'unbound-binary-baseline'
WORK = ROOT / 'output' / 'bootstrap-loop'
WORK.mkdir(parents=True, exist_ok=True)

# ---- zones ----
zones = {
    'example.com': (
        '$ORIGIN example.com.\n$TTL 3600\n'
        '@  IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 1200 604800 3600 )\n'
        '@  IN NS  ns1.example.com.\n'
        'ns1 IN CNAME ns1.example.net.\n'),
    'example.net': (
        '$ORIGIN example.net.\n$TTL 3600\n'
        '@  IN SOA ns1.example.net. hostmaster.example.net. ( 1 3600 1200 604800 3600 )\n'
        '@  IN NS  ns1.example.net.\n'
        'ns1 IN CNAME ns1.example.com.\n'),
    'good.com': (
        '$ORIGIN good.com.\n$TTL 3600\n'
        '@  IN SOA ns1.good.com. hostmaster.good.com. ( 1 3600 1200 604800 3600 )\n'
        '@  IN NS  ns1.good.com.\n'
        'ns1 IN A 192.0.2.1\n'
        'www IN A 192.0.2.80\n'),
}
zonefiles = {}
for name, content in zones.items():
    p = WORK / (name + '.zone')
    p.write_text(content)
    zonefiles[name] = p


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


port_a = free_port()
port_b = free_port()

# ---- A: authoritative ----
conf_a = WORK / 'a.conf'
auth_zone_blocks = ''.join(
    f'auth-zone:\n  name: "{name}."\n  zonefile: "{zonefiles[name]}"\n  fallback-enabled: no\n'
    for name in zones)
conf_a.write_text(
    'server:\n'
    f'  interface: 127.0.0.1@{port_a}\n'
    '  do-daemonize: no\n  username: ""\n  chroot: ""\n  directory: ""\n  pidfile: ""\n'
    '  logfile: ""\n  use-syslog: no\n  verbosity: 1\n'
    '  do-udp: yes\n  do-tcp: yes\n  do-ip6: no\n'
    '  access-control: 127.0.0.0/8 allow\n'
    '  module-config: "iterator"\n'
    + auth_zone_blocks)

# ---- B: recursive ----
conf_b = WORK / 'b.conf'
stub_blocks = ''.join(
    f'stub-zone:\n  name: "{name}."\n  stub-addr: 127.0.0.1@{port_a}\n'
    for name in ['example.com', 'example.net', 'good.com'])
conf_b.write_text(
    'server:\n'
    f'  interface: 127.0.0.1@{port_b}\n'
    '  do-daemonize: no\n  username: ""\n  chroot: ""\n  directory: ""\n  pidfile: ""\n'
    '  logfile: ""\n  use-syslog: no\n  verbosity: 4\n'
    '  do-udp: yes\n  do-tcp: yes\n  do-ip6: no\n'
    '  do-not-query-localhost: no\n'
    '  access-control: 127.0.0.0/8 allow\n'
    '  module-config: "iterator"\n'
    + stub_blocks)


def start(binary, conf, logdir, tag):
    out = (logdir / (tag + '.stdout')).open('wb')
    err = (logdir / (tag + '.stderr')).open('wb')
    proc = subprocess.Popen([str(binary), '-c', str(conf)], stdout=out, stderr=err,
                            cwd=logdir, start_new_session=True)
    return proc, out, err


def wait_listen(port, proc, err_file, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            s = socket.create_connection(('127.0.0.1', port), timeout=0.1)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    err_file.flush()
    print('startup stderr tail:', Path(err_file.name).read_text(errors='replace')[-500:])
    return False


def dns_query(qname, qtype=1):
    header = struct.pack('>HHHHHH', 0x7777, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack('>HH', qtype, 1)


def udp_query(port, payload, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(payload, ('127.0.0.1', port))
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        data = b''
    s.close()
    return data


def rcode(resp):
    if len(resp) < 6:
        return None, None
    flags = struct.unpack('>H', resp[2:4])[0]
    return (flags >> 15) & 1, flags & 0xF


proc_a = proc_b = None
try:
    proc_a, out_a, err_a = start(BINARY, conf_a, WORK, 'a')
    if not wait_listen(port_a, proc_a, err_a):
        raise RuntimeError('instance A failed to start')
    proc_b, out_b, err_b = start(BINARY, conf_b, WORK, 'b')
    if not wait_listen(port_b, proc_b, err_b):
        raise RuntimeError('instance B failed to start')

    tests = [
        ('NS-target ns1.example.com A', dns_query(b'\x03ns1\x07example\x03com\x00', 1)),
        ('www.example.com A', dns_query(b'\x03www\x07example\x03com\x00', 1)),
        ('www.good.com A (control)', dns_query(b'\x03www\x04good\x03com\x00', 1)),
    ]
    print('== querying recursive resolver B ==')
    for label, payload in tests:
        resp = udp_query(port_b, payload)
        qr, rc = rcode(resp)
        rcodes = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
        print(f'  {label:35s} -> QR={qr} RCODE={rcodes.get(rc, rc)} ({rc})')

    time.sleep(0.3)
    err_b.flush()
    log = Path(err_b.name).read_text(errors='replace')
    print('\n== recursive resolver B log (loop evidence) ==')
    hits = [l for l in log.splitlines()
            if 'ns1.example.com' in l or 'ns1.example.net' in l or 'cname' in l.lower()
            or 'cycle' in l.lower() or 'servfail' in l.lower()]
    for l in hits[:60]:
        print('  ', l[:160])
    if not hits:
        print('  (no matching log lines; see full stderr)')
        print(log[-2000:])
finally:
    for proc in (proc_a, proc_b):
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
