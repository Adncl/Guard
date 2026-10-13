"""Hand-pick the highest-value, server-observable DNS rules for the Unbound run."""
import difflib
import io
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pool = json.loads((ROOT / 'output' / 'rules_unbound_dns.json').read_text(encoding='utf-8'))

# Ordered, specific high-value requirements (each tuple is a regex + pick count).
PICKS = [
    (r'63 characters or less', 1),
    (r'case-insensitive manner', 1),
    (r'Z field .* zero in all queries', 1),
    (r'high order two bits of every .* length octet MUST be zero', 1),
    (r'zone refresh activities MUST use virtual circuits', 1),
    (r'directed to the port from which they were sent', 1),
    (r'never merge RRs', 1),
    (r'TTLs of all RRs in an RRSet MUST be the same', 1),
    (r'NS resource record MUST NOT be an alias', 1),
    (r'value of a PTR .* MUST NOT be an alias', 1),
    (r'SOA record of the zone in the authority section', 1),
    (r'MUST also cache negative answers', 1),
    (r'cached SOA record MUST be added to the response', 1),
    (r'Name error indications MUST be cached', 1),
    (r'No data indications MUST be cached', 1),
]


def norm(text):
    body = re.sub(r'\[RFC \d+\]\s*', '', text)
    body = re.sub(r'[^a-z0-9]', '', body.lower())
    return body[:90]


chosen, keys = [], []
for pattern, count in PICKS:
    matches = [r for r in pool if re.search(pattern, r['rule']) and re.search(r'\b(MUST|SHALL|REQUIRED)\b', r['rule'])]
    taken = 0
    for r in matches:
        if taken >= count:
            break
        k = norm(r['rule'])
        if any(difflib.SequenceMatcher(None, k, p).ratio() >= 0.8 for p in keys):
            continue
        keys.append(k)
        chosen.append(r)
        taken += 1

out = ROOT / 'output' / 'rules_unbound_dns_run.json'
out.write_text(json.dumps(chosen, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'final': len(chosen)}, indent=2))
for i, r in enumerate(chosen, 1):
    print(f'{i:2d}.', r['rule'][:110])
