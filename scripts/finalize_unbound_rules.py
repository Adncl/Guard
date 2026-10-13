"""Deduplicate and finalize the Unbound DNS rules for slicing/detection.

The LLM contextualization over-splits and re-prefixes candidates into many
near-duplicate rules. Collapse semantic duplicates, drop resolver-internal
guidance, and keep the wire-observable server-side requirements.
"""
import difflib
import io
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rules = json.loads((ROOT / 'output' / 'rules_unbound_dns.json').read_text(encoding='utf-8'))

INTERNAL = re.compile(
    r'hash structures|concurrent activities|routing tables|round trip time|multiplex|'
    r'This structure|amount of work|initialize their routing|HOSTS.TXT|copyright|'
    r'proper subset|bit map MUST|case sensitive data MUST be minimized|'
    r'size of the serial number space MUST be given', re.I)


def norm(text):
    body = re.sub(r'^(DNS|RFC ?1035( [\d.]+)?|RFC ?2181( [\d.]+)?|RFC ?2308( [\d.]+)?|'
                  r'RFC ?4343( [\d.]+)?|RFC ?1982( [\d.]+)?)[:\s]*', '', text, flags=re.I)
    body = re.sub(r'\[RFC \d+\]\s*', '', body)
    body = re.sub(r'\b(must not|must|shall not|shall|required|not|the|a|an|of|to|for|and|or|in|is|are|be|this|that|its)\b',
                  '', body.lower())
    body = re.sub(r'[^a-z0-9]', '', body)
    return body[:140]


kept, keys = [], []
for rule in rules:
    text = rule['rule'].strip()
    if not text or INTERNAL.search(text):
        continue
    if not re.search(r'\b(MUST|SHALL|REQUIRED)\b', text):
        continue
    k = norm(text)
    if not k or any(difflib.SequenceMatcher(None, k, p).ratio() >= 0.78 for p in keys):
        continue
    keys.append(k)
    kept.append(rule)

# Prioritize concrete request types and cap the set for a bounded experiment.
with_type = [r for r in kept if r.get('req_type')]
without_type = [r for r in kept if not r.get('req_type')]
kept = with_type + without_type
cap = 40
kept = kept[:cap]

out = ROOT / 'output' / 'rules_unbound_dns_final.json'
out.write_text(json.dumps(kept, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'final': len(kept), 'total': len(rules)}, indent=2))
for i, r in enumerate(kept, 1):
    print(f'{i:2d}. [{r["req_type"] or "-":6}]', r['rule'][:105])
