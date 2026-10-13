"""Select wire-format DNS rules for Unbound consistency testing.

The full RFC 1035 extraction yields 185 rules, many of which are resolver
implementation guidance with no observable wire behavior. The Unbound case
slices and detects the wire-format subset; near-duplicate rule texts are
collapsed to their first occurrence.
"""
import io
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rules = json.loads((ROOT / 'output' / 'rules_unbound_dns.json').read_text(encoding='utf-8'))

WIRE = re.compile(
    r'\b(label|labels|octet|octets|compression|pointer|QDCOUNT|ANCOUNT|NSCOUNT|ARCOUNT|'
    r'header|opcode|OPCODE|rcode|RCODE|truncat|63 char|63 octet|255 octet|'
    r'case.insensitive|inverse|virtual circuit|TCP|UDP)\b'
    r'|zero in all queries', re.I)
STRONG = re.compile(r'\bMUST\b|\bSHALL\b|\bREQUIRED\b')
EXCLUDE = re.compile(r'multiple concurrent activities|hash structures|round trip time', re.I)

def key(text):
    # Collapse LLM prefix noise and punctuation for near-duplicate detection.
    body = re.sub(r'^(DNS 1035|RFC ?1035( [\d.]+)?|RFC 1035)[:\s]*', '', text)
    body = re.sub(r'\b(must|shall|not|the|a|an|of|to|for|and|or|in)\b', '', body.lower())
    body = re.sub(r'[^a-z0-9]', '', body)
    return body[:120]

import difflib
def similar(needle, haystacks):
    return any(difflib.SequenceMatcher(None, needle, h).ratio() >= 0.75 for h in haystacks)

selected, seen = [], set()
for rule in rules:
    text = rule['rule']
    if not WIRE.search(text) or not STRONG.search(text) or EXCLUDE.search(text):
        continue
    if key(text) in seen:
        continue
    seen.add(key(text))
    selected.append(rule)

out = ROOT / 'output' / 'rules_unbound_dns_selected.json'
out.write_text(json.dumps(selected, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'selected': len(selected), 'total': len(rules), 'output': str(out)}, indent=2))
for i, r in enumerate(selected, 1):
    print(f'{i:2d}.', r['rule'][:120])
