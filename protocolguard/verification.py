"""Generate assertion patches and Scapy seeds, compile, and replay against Sol."""
import argparse
import difflib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from .common import (LLM, ROOT, connect, database_path, experiment_identity,
                     file_sha256, load_config, read_rules, verification_path)
from .packets import extract_payload


def command(args, cwd=None, timeout=180):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args[0]}\n' + (result.stdout + result.stderr)[-16000:])
    return result.stdout + result.stderr


def remove_instrumentation(text):
    text = re.sub(r'(?ms)^\s*#ifdef ASSERT_ENABLED\b.*?^\s*#endif[^\n]*\n?', '', text)
    text = re.sub(r'(?m)^\s*#include\s*[<"]assert.h[>"]\s*$', '', text)
    # Whitespace inside C strings/characters is semantic (e.g. "a b" != "ab").
    return tuple(re.findall(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d+|[^\s]', text))


def selected_violations(db, config):
    """Reject stale evidence and never consume rows from a different rule set."""
    identity = experiment_identity(config)
    active = {r['rule'] for r in read_rules(config['project']['rule_path'])}
    rows = []
    for rule, raw in db.execute('SELECT rule_desc,llm_response FROM rule_code_snippet ORDER BY rule_desc'):
        if rule not in active or not raw:
            continue
        report = json.loads(raw)
        if report.get('provenance', {}).get('identity') != identity:
            raise ValueError('Detection provenance is missing or stale; rerun slice and detect')
        if report.get('result') == 'violation found!':
            rows.append((rule, report))
    if {r[0] for r in db.execute('SELECT rule_desc FROM rule_code_snippet WHERE llm_response != ?', ('',))} & active != active:
        raise ValueError('Some active rules have no detection result')
    return rows


def mqtt_frames(payload):
    frames = []
    offset = 0
    while offset < len(payload):
        header = payload[offset]
        offset += 1
        length, multiplier = 0, 1
        for _ in range(4):
            if offset == len(payload):
                raise ValueError('Truncated MQTT remaining length')
            byte = payload[offset]
            offset += 1
            length += (byte & 127) * multiplier
            multiplier *= 128
            if not byte & 128:
                break
        else:
            raise ValueError('Invalid MQTT remaining length')
        if offset + length > len(payload):
            raise ValueError('Truncated MQTT packet')
        frames.append((header, payload[offset:offset + length]))
        offset += length
    return frames


def canonical_positive_payload():
    """A fixed, independently known-good MQTT 3.1.1 CONNECT + PINGREQ."""
    return bytes.fromhex('101500044d5154540402003c00097067636f6e74726f6cc000')


def canonical_mqtt5_positive_payload():
    """A fixed, independently known-good MQTT 5.0 CONNECT + PINGREQ."""
    # CONNECT: protocol level 5, clean start, empty CONNECT properties, and
    # the deterministic client id pgcontrol; followed by PINGREQ.
    return bytes.fromhex('101600044d5154540502003c0000097067636f6e74726f6cc000')


def dns_frames(payload):
    """Split a DNS-over-TCP byte stream into length-prefixed messages."""
    frames, offset = [], 0
    while offset + 2 <= len(payload):
        length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        if length == 0 or offset + length > len(payload):
            break
        frames.append(payload[offset:offset + length])
        offset += length
    return frames


def _dns_flags(message):
    if len(message) < 12:
        return None
    qr = (message[2] >> 7) & 1
    rcode = message[3] & 0x0F
    return qr, rcode


def dns_positive_payload():
    """A fixed, independently known-good DNS-over-TCP A query for pgcontrol.test."""
    import struct
    qname = b'\x09pgcontrol\x04test\x00'
    header = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)  # id, RD=1, QDCOUNT=1
    message = header + qname + struct.pack('>HH', 1, 1)          # QTYPE=A, QCLASS=IN
    return struct.pack('>H', len(message)) + message


def protocol_adapter(config):
    """Return the target/protocol-specific pieces required by replay.

    The static pipeline is target independent, but the paper's dynamic phase
    necessarily needs a concrete executable, startup configuration, positive
    oracle, and wire-level witness for each protocol implementation.
    """
    identity = (config['project']['project_name'], config['project']['protocol_name'],
                config['project']['protocol_version'])
    if identity == ('Sol', 'MQTT', '3.1.1'):
        return {
            'kind': 'sol', 'binary': ROOT / 'output/sol-build/sol',
            'positive_payload': canonical_positive_payload,
            'positive_response': bytes.fromhex('20020000d000'),
            'source_headers': {'mqtt.h', 'sol_internal.h', 'handlers.h'},
            'protocol_prompt': 'MQTT 3.1.1',
            'scapy_layer': 'scapy.contrib.mqtt or programmatic struct serialization',
            'scapy_positive': 'Client Identifier pgcontrol, a valid MQTT 3.1.1 CONNECT with clean session, then PINGREQ',
            'tshark_args': ['-d', 'tcp.port==18883,mqtt', '-Y', 'mqtt', '-T', 'fields', '-e', 'mqtt.msgtype'],
        }
    if identity == ('Mosquitto', 'MQTT', '5.0'):
        return {
            'kind': 'mosquitto', 'binary': ROOT / 'output/mosquitto-build/src/mosquitto',
            'positive_payload': canonical_mqtt5_positive_payload,
            'positive_response': None,
            'source_headers': {'mqtt_protocol.h', 'mosquitto_broker_internal.h',
                               'packet_mosq.h', 'property_mosq.h', 'mosquitto_internal.h',
                               'net_mosq.h', 'send_mosq.h', 'read_handle.h', 'util_mosq.h'},
            'protocol_prompt': 'MQTT 5.0',
            'scapy_layer': 'scapy.contrib.mqtt or programmatic struct serialization',
            'scapy_positive': 'Client Identifier pgcontrol, a valid MQTT 5.0 CONNECT with clean session, then PINGREQ',
            'tshark_args': ['-d', 'tcp.port==18883,mqtt', '-Y', 'mqtt', '-T', 'fields', '-e', 'mqtt.msgtype'],
        }
    if identity == ('Unbound', 'DNS', '1035-2308'):
        return {
            'kind': 'unbound', 'binary': ROOT / 'output/unbound-binary-baseline',
            'positive_payload': dns_positive_payload,
            'positive_response': None,
            'source_headers': {'config.h', 'util/netevent.h', 'util/net_help.h',
                               'util/data/msgreply.h', 'util/data/msgparse.h',
                               'util/data/msgencode.h', 'sldns/pkthdr.h', 'sldns/rrdef.h'},
            'protocol_prompt': 'DNS (RFC 1035/2181/4343/2308/1982)',
            'scapy_layer': 'scapy.layers.dns (DNS/DNSQR) or programmatic struct serialization with a 2-byte length prefix',
            'scapy_positive': 'a valid DNS-over-TCP query for the A record of pgcontrol.test with RD set and QDCOUNT=1',
            'tshark_args': ['-d', 'tcp.port==18883,dns', '-Y', 'dns', '-T', 'fields',
                            '-e', 'dns.flags.response', '-e', 'dns.flags.rcode'],
        }
    if identity == ('BIND9', 'DNS', '1035-2308'):
        return {
            'kind': 'bind9', 'binary': ROOT / 'output/bind9-binary-baseline',
            'positive_payload': dns_positive_payload,
            'positive_response': None,
            'source_headers': {'isc/util.h', 'isc/result.h', 'dns/name.h', 'dns/rdata.h',
                               'dns/rdataset.h', 'dns/zone.h', 'dns/view.h', 'dns/message.h',
                               'dns/compress.h', 'dns/rdataclass.h', 'dns/rdatatype.h',
                               'ns/client.h', 'ns/query.h', 'ns/interfacemgr.h'},
            'protocol_prompt': 'DNS (RFC 1035/2181/4343/2308/1982)',
            'scapy_layer': 'scapy.layers.dns (DNS/DNSQR) or programmatic struct serialization with a 2-byte length prefix',
            'scapy_positive': 'a valid DNS-over-TCP query for the A record of pgcontrol.test with RD set and QDCOUNT=1',
            'tshark_args': ['-d', 'tcp.port==18883,dns', '-Y', 'dns', '-T', 'fields',
                            '-e', 'dns.flags.response', '-e', 'dns.flags.rcode'],
        }
    raise ValueError('No dynamic adapter is registered for ' + repr(identity))


def _mqtt_packet_type(header):
    return header >> 4


def _mqtt5_subscribe_qos(body):
    """Decode requested QoS values from a MQTT 5 SUBSCRIBE body."""
    if len(body) < 3:
        return []
    pos = 0
    try:
        packet_id = body[pos:pos + 2]
        pos += 2
        # Properties are a variable byte integer.
        prop_len = 0
        mult = 1
        while True:
            b = body[pos]
            pos += 1
            prop_len += (b & 127) * mult
            if not b & 128:
                break
            mult *= 128
            if mult > 128 * 128 * 128:
                return []
        pos += prop_len
        values = []
        while pos + 2 <= len(body):
            n = (body[pos] << 8) | body[pos + 1]
            pos += 2 + n
            if pos >= len(body):
                break
            values.append(body[pos] & 3)
            pos += 1
        return values
    except (IndexError, ValueError):
        return []


def baseline_witness(rule, replay_result, adapter):
    """Independent wire evidence for the three explicitly supported demo rules.

    A generated assertion firing alone is not proof of a protocol violation.
    Unknown or silent cases remain unconfirmed.
    """
    if adapter['kind'] == 'unbound' or adapter['kind'] == 'bind9':
        # Silent acceptance: the baseline resolver answered the rule-violating
        # counterexample with a normal NOERROR response (QR=1, RCODE=0) instead
        # of FORMERR/REFUSED/NOTIMP. This is a coarse wire signal; per-rule
        # refinement belongs in a protocol-specific witness.
        frames = dns_frames(bytes.fromhex(replay_result['response_hex']))
        return any(flags == (1, 0) for flags in (_dns_flags(m) for m in frames) if flags is not None)
    frames = mqtt_frames(bytes.fromhex(replay_result['payload_hex']))
    replies = mqtt_frames(bytes.fromhex(replay_result['response_hex']))
    if replay_result['returncode_before_cleanup'] is not None:
        return False
    if adapter['kind'] == 'sol' and re.search(r'MQTT-3\.1\.2-3\b', rule):
        return (len(frames) == 1 and frames[0][0] == 0x10 and len(frames[0][1]) >= 10
                and frames[0][1][:7] == b'\x00\x04MQTT\x04'
                and bool(frames[0][1][7] & 1) and (0x20, b'\x00\x00') in replies)
    if adapter['kind'] == 'sol' and re.search(r'MQTT-3\.1\.0-1\b', rule):
        return bool(frames and frames[0] == (0xc0, b'') and (0xd0, b'') in replies)
    if adapter['kind'] == 'sol' and re.search(r'MQTT-3\.1\.0-2\b', rule):
        return (sum(header == 0x10 for header, _ in frames) >= 2
                and sum(header == 0x20 and body[-1:] == b'\x00' for header, body in replies) >= 2)
    if adapter['kind'] == 'mosquitto':
        lowered = rule.lower()
        types = [_mqtt_packet_type(header) for header, _ in frames]
        reply_types = [_mqtt_packet_type(header) for header, _ in replies]
        # The four Mosquitto findings reported in the paper are all silent
        # acceptance/state errors.  A successful SUBACK/PUBLISH on the
        # malformed sequence is independent wire evidence; an assertion alone
        # is not treated as proof.
        if 'share name' in lowered:
            payload = bytes.fromhex(replay_result['payload_hex'])
            share_names = re.findall(rb'\$share/([^/]+)/', payload)
            malformed_share = any(b'+' in name or b'#' in name for name in share_names)
            return (malformed_share and 8 in types and 9 in reply_types
                    and 14 not in reply_types
                    and any(body and all(code < 0x80 for code in body[-4:])
                            for header, body in replies if _mqtt_packet_type(header) == 9))
        if 'subscription identifier' in lowered:
            return ('0b00' in replay_result['payload_hex'].lower() and 8 in types
                    and 9 in reply_types and 14 not in reply_types)
        if 'overlapping subscriptions' in lowered:
            requested = [q for header, body in frames if _mqtt_packet_type(header) == 8
                         for q in _mqtt5_subscribe_qos(body)]
            delivered = [(header >> 1) & 3 for header, _ in replies
                         if _mqtt_packet_type(header) == 3]
            return (len(requested) >= 2 and max(requested) >= 1 and bool(delivered)
                    and any(q < max(requested) for q in delivered))
        if 'topic alias' in lowered:
            # CONNECT property 0x22 is Topic Alias Maximum; a value of zero
            # forbids aliases in server-to-client PUBLISH packets.  The
            # corresponding malformed wire witness contains a 0x23 alias.
            payload = bytes.fromhex(replay_result['payload_hex'])
            return (b'\x22\x00\x00' in payload and 0x23 in payload
                    and any(_mqtt_packet_type(h) == 3 and 0x23 in body for h, body in replies))
    return False


def positive_control_ok(result, adapter):
    """Validate a deterministic positive control without overfitting fields."""
    if result['returncode_before_cleanup'] is not None or result['assertion_failure']:
        return False
    if adapter['kind'] == 'unbound':
        frames = dns_frames(bytes.fromhex(result['response_hex']))
        return any(flags == (1, 0) for flags in (_dns_flags(m) for m in frames) if flags is not None)
    frames = mqtt_frames(bytes.fromhex(result['response_hex']))
    if adapter['kind'] == 'sol':
        return result['response_hex'] == adapter['positive_response'].hex()
    if adapter['kind'] == 'mosquitto':
        # MQTT 5 CONNACK: session-present flag 0 and Success reason code,
        # followed by a PINGRESP. Properties are implementation-defined.
        return (frames and _mqtt_packet_type(frames[0][0]) == 2
                and len(frames[0][1]) >= 3 and frames[0][1][0] == 0
                and frames[0][1][1] == 0
                and any(header == 0xd0 and not body for header, body in frames))
    return False


def apply_edits(root, edits):
    changed = {}
    if not isinstance(edits, list) or not edits:
        raise ValueError('Assertion generation returned no edits')
    for edit in edits:
        path = (root / edit['file']).resolve()
        if not path.is_relative_to(root.resolve()) or path.suffix not in ('.c', '.h') or not path.is_file():
            raise ValueError('Edit must target a C source file within the experiment source tree')
        old = changed.get(path, path.read_text())
        before, after = edit['before'], edit['after']
        if not before or old.count(before) != 1:
            raise ValueError('Edit anchor must match exactly once')
        updated = old.replace(before, after, 1)
        if remove_instrumentation(old) != remove_instrumentation(updated):
            raise ValueError('Instrumentation must preserve the original program when ASSERT_ENABLED is absent')
        changed[path] = updated
    if not any('assert(' in value or 'assert (' in value for value in changed.values()):
        raise ValueError('No executable assertion generated')
    for path, text in changed.items():
        path.write_text(text)
    return changed


def compile_sol(source, build):
    command(['cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_C_COMPILER=clang-14',
             '-DCMAKE_CXX_COMPILER=clang++-14',
             '-DCMAKE_C_FLAGS=-DASSERT_ENABLED=1 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable'])
    return command(['cmake', '--build', build, '-j', '2'])


def compile_target(source, build, adapter):
    if adapter['kind'] == 'sol':
        return compile_sol(source, build)
    if adapter['kind'] == 'mosquitto':
        return command(['cmake', '-S', source, '-B', build, '-G', 'Ninja',
                        '-DCMAKE_C_COMPILER=clang-14', '-DCMAKE_CXX_COMPILER=clang++-14',
                        '-DCMAKE_C_FLAGS=-DASSERT_ENABLED=1 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable',
                        '-DCMAKE_CXX_FLAGS=-DASSERT_ENABLED=1',
                        '-DWITH_CLIENTS=OFF', '-DWITH_APPS=OFF', '-DWITH_PLUGINS=OFF',
                        '-DWITH_CJSON=OFF', '-DDOCUMENTATION=OFF', '-DWITH_LIB_CPP=OFF',
                        '-DWITH_BUNDLED_DEPS=ON', '-DWITH_TLS=ON']) + command(
                            ['cmake', '--build', build, '-j', '2'])
    if adapter['kind'] == 'unbound':
        for name in ['configure', 'install-sh', 'config.guess', 'config.sub',
                     'missing', 'compile', 'depcomp', 'ltmain.sh']:
            p = source / name
            if p.is_file():
                p.chmod(0o755)
        command(['./configure', 'CC=clang-14',
                 'CFLAGS=-DASSERT_ENABLED=1 -g -O1 -Wno-error=deprecated-declarations -Wno-error=unused-but-set-variable'],
                cwd=source, timeout=300)
        return command(['make', '-j', '2'], cwd=source, timeout=900)
    if adapter['kind'] == 'bind9':
        meson_build = build / 'meson-build'
        meson_build.mkdir(parents=True, exist_ok=True)
        command(['meson', 'setup', str(source), '--prefix=' + str(build / 'install'),
                 '-Dbuildtype=debug'],
                cwd=str(meson_build), timeout=300)
        return command(['ninja', '-j', '2', '-C', str(meson_build)], timeout=900)
    raise ValueError('Unknown dynamic adapter kind: ' + adapter['kind'])


def replay(binary, payload, log_dir, label, adapter):
    log_dir = Path(log_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    config = log_dir / f'{label}.conf'
    logfile = log_dir / (label + '.server.log')
    if adapter['kind'] == 'mosquitto':
        # The broker drops privileges before opening file destinations.  Send
        # the complete broker log to stderr so the replay artifact remains
        # readable and does not depend on a host-side mosquitto user.
        config.write_text(f'listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\nlog_type all\nlog_dest stderr\n')
    elif adapter['kind'] == 'unbound':
        config.write_text(
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
            '  verbosity: 1\n'
            '  access-control: 127.0.0.0/8 allow\n'
            '  local-zone: "pgcontrol.test." static\n'
            '  local-data: "pgcontrol.test. 60 IN A 127.0.0.1"\n'
            '  qname-minimisation: no\n'
            '  val-permissive-mode: yes\n')
    elif adapter['kind'] == 'bind9':
        # BIND9 named.conf for authoritative replay
        zonefile = log_dir / 'pgcontrol.test.zone'
        zonefile.write_text(
            '$ORIGIN pgcontrol.test.\n$TTL 60\n'
            '@ IN SOA ns1.pgcontrol.test. hostmaster.pgcontrol.test. (1 3600 1200 604800 60)\n'
            '@ IN NS ns1.pgcontrol.test.\nns1 IN A 127.0.0.1\n')
        config.write_text(
            f'options {{\n'
            f'  directory "{log_dir}";\n'
            f'  listen-on port {port} {{ 127.0.0.1; }};\n'
            f'  listen-on-v6 {{ none; }};\n'
            f'  pid-file "{log_dir}/named.pid";\n'
            f'  allow-query {{ any; }};\n'
            f'  recursion no;\n'
            f'  auth-nxdomain no;\n'
            f'}};\n'
            f'\n'
            f'zone "pgcontrol.test" IN {{\n'
            f'  type master;\n'
            f'  file "{zonefile}";\n'
            f'}};\n')
    else:
        config.write_text(f'ip_address 127.0.0.1\nip_port {port}\nlog_level DEBUG\nlog_path {logfile}\n')
    stdout_path = log_dir / f'{label}.stdout'
    stderr_path = log_dir / f'{label}.stderr'
    response = b''
    returncode_after_cleanup = None
    # BIND9 named requires -g (log to stderr) and -f (foreground)
    cmd = [str(binary), '-c', str(config)]
    if adapter['kind'] == 'bind9':
        cmd += ['-g', '-f']
    with stdout_path.open('wb') as out, stderr_path.open('wb') as err:
        process = subprocess.Popen(cmd, stdout=out, stderr=err, cwd=log_dir,
                                    start_new_session=True)
        connected = False
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    sock = socket.create_connection(('127.0.0.1', port), timeout=0.1)
                    connected = True
                    break
                except OSError:
                    time.sleep(0.02)
            if not connected:
                raise RuntimeError('Target did not open a local socket: ' + stderr_path.read_text())
            with sock:
                sock.settimeout(0.5)
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
            returncode = process.poll()
            if returncode is None:
                # An assertion abort can land just after the first poll; wait
                # briefly for a self-exit before attributing the shutdown to
                # the cleanup signal below.
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    returncode = process.poll()
                    if returncode is not None:
                        break
                    time.sleep(0.05)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            returncode_after_cleanup = process.returncode
    stderr = stderr_path.read_text(errors='replace')
    # Assertions may be raised by a worker thread while the event-loop parent
    # has not reaped the child at the first poll.  The stderr diagnostic is the
    # authoritative witness; retain both return codes for auditability.
    assertion_failure = ('Assertion' in stderr and 'failed.' in stderr)
    return {'returncode_before_cleanup': returncode,
            'returncode_after_cleanup': returncode_after_cleanup,
            'response_hex': response.hex(),
            'assertion_failure': assertion_failure,
            'stderr': stderr, 'payload_hex': payload.hex()}


def verify(config, rule_filter=None):
    adapter = protocol_adapter(config)
    db = connect(database_path(config))
    rows = selected_violations(db, config)
    if rule_filter:
        rows = [row for row in rows if rule_filter in row[0]]
        if not rows:
            raise ValueError('Requested rule is not a current detected violation')
    if not rows:
        raise ValueError('No detected violation is available for dynamic verification')
    llm = LLM(config, db)
    original = Path(config['project']['project_path'])
    work = verification_path(config)
    work.mkdir(parents=True, exist_ok=True)
    # Preserve earlier runs instead of allowing partial retries to inherit their results.
    from datetime import datetime, timezone
    work = work / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    work.mkdir()
    summaries = []
    for i, (rule, report) in enumerate(rows, 1):
        case = work / f'rule_{i}'
        source = case / 'source'
        case.mkdir(parents=True, exist_ok=True)
        evidence = {}
        # Source context is real file content, with exact edit anchors.
        for violation in report['violations']:
            path = Path(violation['filename'])
            if not path.resolve().is_relative_to(original.resolve()):
                raise ValueError('Violation source must be inside configured project')
            relative = path.relative_to(original)
            evidence[str(relative)] = path.read_text()
        for path in original.rglob('*.h'):
            if not adapter['source_headers'] or path.name in adapter['source_headers']:
                evidence[str(path.relative_to(original))] = path.read_text()
        prompt = f'''Generate conditional C assertions to expose this protocol implementation inconsistency.
Rule: {rule}
Report: {json.dumps(report)}
Return {{"edits":[{{"file":"relative/file.c","before":"exact unique original substring","after":"replacement"}}],"oracle_reason":"..."}}.
Preserve original semantics when ASSERT_ENABLED is undefined. ONLY add assertion instrumentation; do not fix the bug.
Wrap ALL new helper functions and assertion statements inside #ifdef ASSERT_ENABLED ... #endif, on separate lines.
Use assert(condition || !"ProtocolGuard: rule identifier"). Include assert.h if missing. Helpers start with assert_related_.
The assertion must witness the implementation processing an input contrary to the rule, not reject an input that the
original program would already handle correctly. Locate assertions at the demonstrated missing validation site.
Target implementation and protocol: {config['project']['project_name']} {adapter['protocol_prompt']}.
Source files: {json.dumps(evidence)}'''
        error = ''
        for attempt in range(5):
            shutil.copytree(original, source, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('build', '.git',
                                                         '*.o', '*.lo', '.libs', '.deps'))
            proposal = llm.query('assertion-generation', prompt + '\nPrevious validation error (if any):\n' + error, reasoning=True)
            try:
                changed = apply_edits(source, proposal['edits'])
                build_log = compile_target(source, case / 'build', adapter)
                (case / 'compile.log').write_text(build_log)
                (case / 'assertions.json').write_text(json.dumps(proposal, indent=2))
                patch = ''.join(''.join(difflib.unified_diff((original / p.relative_to(source)).read_text().splitlines(True),
                              text.splitlines(True), fromfile=str(p.relative_to(source)), tofile=str(p.relative_to(source)))) for p, text in changed.items())
                (case / 'assertions.patch').write_text(patch)
                break
            except (ValueError, RuntimeError) as e:
                error = str(e)
                if attempt == 4:
                    raise
        sequence = llm.query('counterexample-sequence', f'''Create minimal message sequences to expose this violation:
Rule: {rule}
Report: {json.dumps(report)}
Return {{"counterexamples":[{{"name":"name","messages":[{{"type":"packet type","fields":{{}}}}],"expected":"..."}}],
"positive_control":{{"messages":[{{"type":"packet type","fields":{{}}}}]}}}}.
Specify concrete field values, lengths and ordering. Do not generate raw bytes.''')
        (case / 'sequences.json').write_text(json.dumps(sequence, indent=2))
        error = ''
        for attempt in range(5):
            pcaps = case / f'pcaps-attempt-{attempt + 1}'
            pcaps.mkdir()
            generated = llm.query('scapy-generation', f'''Write an offline Python Scapy script to serialize these {adapter['protocol_prompt']} message sequences to PCAP.
Sequences: {json.dumps(sequence)}
Return {{"script":"complete Python source"}}. The script runs in the output directory.
Write counterexample_1.pcap (and more if needed) and positive.pcap. Use IP 127.0.0.1,
client TCP port 30000, server TCP port 18883. Set TCP sequence numbers correctly for concatenation.
Use {adapter['scapy_layer']}. Write files with wrpcap; do not use send/sniff/network IO.
Each PCAP must contain one client-to-server flow with its complete application sequence.
For the positive control use {adapter['scapy_positive']}.
Previous script validation error: {error}''')
            script = pcaps / 'generate.py'
            script.write_text(generated['script'])
            try:
                clean_env = {k: v for k, v in os.environ.items() if not re.search(r'KEY|TOKEN|SECRET', k, re.I)}
                result = subprocess.run([sys.executable, str(script)], cwd=pcaps, env=clean_env, capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise ValueError(result.stderr[-8000:])
                captures = list(pcaps.glob('counterexample_*.pcap'))
                if not captures or not (pcaps / 'positive.pcap').is_file():
                    raise ValueError('Script must create counterexamples and a positive control')
                payloads = {p.stem: extract_payload(p, 18883) for p in [*captures, pcaps / 'positive.pcap']}
                # LLM-produced positive controls are untrusted test inputs. A
                # malformed positive must never turn a valid assertion into a
                # false negative, so use the independently fixed adapter
                # control sequence and retain the generated PCAP for audit.
                payloads['positive'] = adapter['positive_payload']()
                for p in [*captures, pcaps / 'positive.pcap']:
                    decoded = command(['tshark', '-r', p, *adapter['tshark_args']])
                    if not decoded.strip():
                        raise ValueError(f'tshark did not decode {adapter["protocol_prompt"]} in ' + p.name)
                    (pcaps / (p.stem + '.tshark.txt')).write_text(decoded)
                break
            except (ValueError, RuntimeError) as e:
                error = str(e)
                if attempt == 4:
                    raise
        tests = {}
        for name, payload in payloads.items():
            (case / (name + '.raw')).write_bytes(payload)
            baseline = replay(adapter['binary'], payload, case / 'replays', name + '-baseline', adapter)
            instrumented_binary = case / {'mosquitto': 'build/src/mosquitto',
                                           'sol': 'build/sol',
                                           'unbound': 'source/unbound'}[adapter['kind']]
            instrumented = replay(instrumented_binary, payload, case / 'replays', name + '-instrumented', adapter)
            tests[name] = {'baseline': baseline, 'instrumented': instrumented}
        positive = tests['positive']
        positive_ok = (positive_control_ok(positive['baseline'], adapter) and
                       positive_control_ok(positive['instrumented'], adapter) and
                       positive['baseline']['response_hex'] == positive['instrumented']['response_hex'])
        triggered = [name for name, result in tests.items() if name != 'positive' and
                     baseline_witness(rule, result['baseline'], adapter) and result['instrumented']['assertion_failure']]
        summary = {'rule': rule, 'positive_control_passed': positive_ok, 'triggered': triggered,
                   'dynamically_verified': bool(triggered) and positive_ok, 'tests': tests,
                   'positive_control_source': f'deterministic {adapter["protocol_prompt"]} positive control',
                   'identity': experiment_identity(config),
                   'baseline_binary_sha256': file_sha256(adapter['binary']),
                   'instrumented_binary_sha256': file_sha256(instrumented_binary),
                   'model_calls': llm.observations,
                   'scope': 'LLM assertion + concrete local TCP replay; fuzzing is recorded separately'}
        (case / 'result.json').write_text(json.dumps(summary, indent=2))
        summaries.append(summary)
        print(f'Rule {i}: verified={summary["dynamically_verified"]}, witnesses={triggered}, positive={positive_ok}')
    (work / 'summary.json').write_text(json.dumps(summaries, indent=2))
    (work.parent / 'latest.json').write_text(json.dumps({'run': work.name, 'identity': experiment_identity(config)}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--rule', help='Verify exactly one rule description from the current database')
    a = p.parse_args()
    verify(load_config(a.config), a.rule)
