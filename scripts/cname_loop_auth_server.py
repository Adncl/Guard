#!/usr/bin/env python3
"""Simple authoritative DNS server serving NS→CNAME loop zone.
Correctly constructs DNS wire-format responses."""

import socket, struct, sys, os, time

def dns_encode_name(name):
    """Encode a DNS name to wire format."""
    parts = name.rstrip('.').split('.')
    result = b''
    for p in parts:
        result += bytes([len(p)]) + p.encode('ascii')
    result += b'\x00'
    return result

def compress_name(name, offset, compression={}):
    """Simple name encoding (no compression for simplicity)."""
    return dns_encode_name(name)

class Zone:
    def __init__(self):
        self.records = {}  # (qname, qtype) -> [rdata_wire, ...]

    def add(self, name, qtype, rdata_wire, ttl=300):
        key = (name.lower(), qtype)
        if key not in self.records:
            self.records[key] = []
        self.records[key].append((ttl, rdata_wire))

    def query(self, qname, qtype):
        """Returns list of (name, qtype, ttl, rdata) for answers."""
        results = []
        key = (qname.lower(), qtype)
        if key in self.records:
            for ttl, rdata in self.records[key]:
                results.append((qname, qtype, ttl, rdata))
        # Also include CNAME if querying for non-CNAME type
        if qtype != 5:  # not CNAME
            cname_key = (qname.lower(), 5)
            if cname_key in self.records:
                for ttl, rdata in self.records[cname_key]:
                    results.append((qname, 5, ttl, rdata))
        return results

def build_response(txid, qname, qtype, qclass, zone, aa=True):
    """Build a complete DNS response packet."""
    # Header
    flags = 0x8000  # QR=1
    if aa:
        flags |= 0x0400  # AA=1
    flags |= 0x0100  # RD=1 (copy from query)
    flags |= 0x0080  # RA=0 (no recursion)

    answers = zone.query(qname, qtype)
    ancount = len(answers)
    nscount = 0
    arcount = 0

    header = struct.pack('!HHHHHH', txid, flags, 1, ancount, nscount, arcount)

    # Question
    qname_wire = dns_encode_name(qname)
    question = qname_wire + struct.pack('!HH', qtype, qclass)

    # Answer
    answer_section = b''
    for name, rtype, ttl, rdata in answers:
        answer_section += dns_encode_name(name)
        answer_section += struct.pack('!HH', rtype, qclass)
        answer_section += struct.pack('!I', ttl)
        answer_section += struct.pack('!H', len(rdata))
        answer_section += rdata

    return header + question + answer_section

def main():
    # Build loop.com zone: NS→CNAME→CNAME→NS loop
    loop_zone = Zone()
    # SOA
    soa_rdata = (
        dns_encode_name('ns1.loop.com') +
        dns_encode_name('admin.loop.com') +
        struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
    )
    loop_zone.add('loop.com', 6, soa_rdata)

    # NS → ns1.loop.com
    loop_zone.add('loop.com', 2, dns_encode_name('ns1.loop.com'))

    # ns1 CNAME → alias1
    loop_zone.add('ns1.loop.com', 5, dns_encode_name('alias1.loop.com'))

    # alias1 CNAME → alias2
    loop_zone.add('alias1.loop.com', 5, dns_encode_name('alias2.loop.com'))

    # alias2 CNAME → ns1 (LOOP!)
    loop_zone.add('alias2.loop.com', 5, dns_encode_name('ns1.loop.com'))

    # Build noloop.com zone (control)
    noloop_zone = Zone()
    soa_rdata2 = (
        dns_encode_name('ns1.noloop.com') +
        dns_encode_name('admin.noloop.com') +
        struct.pack('!IIIII', 2026100901, 3600, 900, 604800, 86400)
    )
    noloop_zone.add('noloop.com', 6, soa_rdata2)
    noloop_zone.add('noloop.com', 2, dns_encode_name('ns1.noloop.com'))
    noloop_zone.add('ns1.noloop.com', 1, struct.pack('!I', 0x7f000001))  # 127.0.0.1
    noloop_zone.add('www.noloop.com', 1, struct.pack('!I', 0x0a000001))  # 10.0.0.1

    zones = {
        'loop.com': loop_zone,
        'noloop.com': noloop_zone,
    }

    def get_zone(qname):
        """Find which zone a query belongs to."""
        name = qname.lower()
        for zname, zone in zones.items():
            if name == zname or name.endswith('.' + zname):
                return zone
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 5355))
    print(f"[AUTH] DNS server on 127.0.0.1:5355", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue

            txid, flags, qdcount = struct.unpack('!HHH', data[:6])
            if (flags >> 15) != 0:  # not a query
                continue

            # Parse question
            offset = 12
            labels = []
            while offset < len(data) and data[offset] != 0:
                label_len = data[offset]
                if label_len == 0 or offset + 1 + label_len > len(data):
                    break
                labels.append(data[offset+1:offset+1+label_len].decode('ascii', errors='replace'))
                offset += 1 + label_len

            qname = '.'.join(labels)
            if offset + 5 <= len(data):
                qtype, qclass = struct.unpack('!HH', data[offset+1:offset+5])
            else:
                continue

            zone = get_zone(qname)
            if zone is None:
                # REFUSED
                resp = struct.pack('!HHHHHH', txid, 0x8005, qdcount, 0, 0, 0)
                qname_enc = dns_encode_name(qname)
                resp += qname_enc + struct.pack('!HH', qtype, qclass)
                sock.sendto(resp, addr)
                print(f"[AUTH] {qname} TYPE{qtype} → REFUSED", flush=True)
                continue

            resp = build_response(txid, qname, qtype, qclass, zone)
            sock.sendto(resp, addr)
            ans_count = len(zone.query(qname, qtype))
            print(f"[AUTH] {qname} TYPE{qtype} → NOERROR ({ans_count} answers)", flush=True)

        except Exception as e:
            print(f"[AUTH] Error: {e}", flush=True)

if __name__ == '__main__':
    main()
