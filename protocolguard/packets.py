"""PCAP request extraction with TCP retransmission removal and stream checks."""
import argparse
from pathlib import Path


def extract_payload(path, server_port, direction='to-server', client_port=None):
    from scapy.all import PcapReader, TCP, UDP, IP, IPv6
    if not 1 <= server_port <= 65535:
        raise ValueError('Server port must be between 1 and 65535')
    flows = {}
    with PcapReader(str(path)) as reader:
        for packet in reader:
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if transport is None or ip is None:
                continue
            to_server = transport.dport == server_port
            from_server = transport.sport == server_port
            if not (to_server or from_server):
                continue
            if direction == 'to-server' and not to_server:
                continue
            if direction in ('from-server', 'to-client') and not from_server:
                continue
            if client_port and (transport.sport if to_server else transport.dport) != client_port:
                continue
            payload = bytes(transport.payload)
            if not payload:
                continue
            key = (ip.src, transport.sport, ip.dst, transport.dport, type(transport).__name__)
            flows.setdefault(key, []).append((int(transport.seq) if isinstance(transport, TCP) else None, payload))
    if not flows:
        raise ValueError('No application payload matched the requested direction')
    if len(flows) > 1:
        raise ValueError('Multiple directional flows selected; split the PCAP or specify a client port and one direction')
    chunks = next(iter(flows.values()))
    if chunks[0][0] is None:
        return b''.join(data for _, data in chunks)
    # Normalize sequence numbers relative to the first observed payload to
    # handle 32-bit wrap, sorting segments before checking overlap and gaps.
    origin = chunks[0][0]
    normalized = [(((seq - origin + 2**31) % 2**32) - 2**31, data) for seq, data in chunks]
    normalized.sort(key=lambda value: value[0])
    base = normalized[0][0]
    out = bytearray()
    for seq, data in normalized:
        offset = seq - base
        if offset > len(out):
            raise ValueError('TCP capture has missing bytes; refusing to create an invalid seed')
        overlap = min(len(data), len(out) - offset)
        if overlap and bytes(out[offset:offset+overlap]) != data[:overlap]:
            raise ValueError('Conflicting retransmission bytes')
        out.extend(data[overlap:])
    return bytes(out)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True)
    p.add_argument('--output')
    p.add_argument('--server-port', required=True, type=int)
    p.add_argument('--client-port', type=int)
    p.add_argument('--direction', choices=['to-server', 'from-server', 'to-client', 'both'], default='to-server')
    a = p.parse_args()
    data = extract_payload(a.input, a.server_port, a.direction, a.client_port)
    path = Path(a.output or a.input + '.raw')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f'Extracted {len(data)} bytes to {path}')


if __name__ == '__main__':
    main()
