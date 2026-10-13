"""Curate the validator-behaviour DNSSEC rules for the Unbound DNSSEC case."""
import difflib
import io
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pool = json.loads((ROOT / 'output' / 'rules_unbound_dnssec.candidates.json').read_text(encoding='utf-8'))

STRONG = re.compile(r'\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b')
PICKS = [
    (r'MUST NOT set the AD bit', 1),
    (r'copy the setting of the CD bit', 1),
    (r'SERVFAIL', 1),
    (r'rrsig_labels', 1),
    (r'Protocol Field MUST have value 3', 1),
    (r'TTL value of an RRSIG RR MUST match', 1),
    (r'Labels field MUST be less than or equal', 1),
    (r'prior to the inception date', 1),
    (r'MUST NOT use DNS name compression on the Signer', 1),
    (r'MUST NOT use DNS name compression on the Next Domain Name', 1),
    (r'disregard RRSIGs', 1),
    (r'MUST be treated as invalid during signature', 1),
    (r'reserved: these bits MUST have value 0', 1),
    (r'Zone Key flag not set MUST NOT be used to verify RRSIGs', 1),
    (r'BAD cache', 1),
]


def norm(text):
    body = re.sub(r'\[RFC \d+\]\s*', '', text)
    body = re.sub(r'\b(must not|must|shall not|shall|required|not|the|a|an|of|to|for|and|or|in|is|are|be|it)\b',
                  '', body.lower())
    body = re.sub(r'[^a-z0-9]', '', body)
    return body[:120]


chosen, keys = [], []
for pattern, count in PICKS:
    taken = 0
    for c in pool:
        s = c['sentence']
        if taken >= count:
            break
        if not STRONG.search(s) or not re.search(pattern, s):
            continue
        k = norm(s)
        if any(difflib.SequenceMatcher(None, k, p).ratio() >= 0.85 for p in keys):
            continue
        keys.append(k)
        chosen.append(c)
        taken += 1

out = ROOT / 'output' / 'rules_unbound_dnssec_curated.json'
out.write_text(json.dumps(chosen, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'curated': len(chosen)}, indent=2))
for i, c in enumerate(chosen, 1):
    print(f'{i:2d}.', c['sentence'][:120])
