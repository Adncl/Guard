"""Rebuild a reduced DNSSEC spec from the curated candidates for extraction."""
import html
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
cands = json.loads((ROOT / 'output' / 'rules_unbound_dnssec_curated.json').read_text(encoding='utf-8'))
body = '\n'.join('<p>' + html.escape(c['sentence']) + '</p>' for c in cands)
(ROOT / 'output' / 'unbound-dnssec-spec-selected.html').write_text(
    '<html><body>\n' + body + '\n</body></html>\n', encoding='utf-8')
print('wrote', len(cands), 'paragraphs')
