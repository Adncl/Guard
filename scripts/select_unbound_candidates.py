"""Curate the strong, wire-observable DNS rules for the Unbound case.

From the full multi-RFC candidate set, keep only MUST/SHALL requirements that a
recursive resolver can observe on the wire (message format, labels, case,
negative caching, SOA/serial handling), drop resolver-internal guidance, and
collapse near-duplicates. Rebuilds a reduced specification so extraction
re-derives exactly this curated candidate set.
"""
import difflib
import io
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
cands = json.loads((ROOT / 'output' / 'rules_unbound_dns.candidates.json').read_text(encoding='utf-8'))

STRONG = re.compile(r'\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b')
WIRE = re.compile(
    r'label|octet|pointer|compress|QDCOUNT|ANCOUNT|NSCOUNT|ARCOUNT|header|opcode|rcode|'
    r'message|quer|respons|SOA|NXDOMAIN|NODATA|NXT|negative|serial|case.insensitive|'
    r'zero in all|virtual circuit|inverse|truncat|TC bit|authority section|answer section|'
    r'name server|TTL|reserved', re.I)
EXCLUDE = re.compile(
    r'concurrent activities|hash structures|routing tables|round trip time|multiplex|'
    r'expected round trip|sample the round trip|This structure keeps track|'
    r'amount of work which a resolver|initialize their routing|HOSTS.TXT|copyright notice|'
    r'this memo suggests|MAY NOT be modified|proper subset of QTYPEs|'
    r'bit map MUST be a multiple|case sensitive data MUST be minimized|'
    r'carried out, or that some behaviour|suggested standard|'
    r'attack to be successful|special care to verify that ALL servers', re.I)


def norm(text):
    body = re.sub(r'\[RFC \d+\]\s*', '', text)
    body = re.sub(r'\b(must not|must|shall not|shall|required|not|the|a|an|of|to|for|and|or|in|is|are|be)\b',
                  '', body.lower())
    body = re.sub(r'[^a-z0-9]', '', body)
    return body[:110]


selected, seen_keys, contexts = [], set(), []
for c in cands:
    s = c['sentence']
    if not STRONG.search(s) or not WIRE.search(s) or EXCLUDE.search(s):
        continue
    k = norm(s)
    if any(difflib.SequenceMatcher(None, k, p).ratio() >= 0.8 for p in seen_keys):
        continue
    seen_keys.add(k)
    selected.append(c)
    if c['context'] not in contexts:
        contexts.append(c['context'])

# Reduced specification so extraction re-derives exactly this curated set.
body = '\n'.join('<p>' + c + '</p>' for c in contexts)
(ROOT / 'output' / 'unbound-spec-selected.html').write_text(
    '<html><body>\n' + body + '\n</body></html>\n', encoding='utf-8')
print(json.dumps({'selected': len(selected), 'contexts': len(contexts)}, indent=2))
for i, c in enumerate(selected, 1):
    print(f'{i:2d}.', c['sentence'][:130])
