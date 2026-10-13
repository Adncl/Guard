"""Download and normalize the DNSSEC RFCs Unbound's validator implements.

Unbound is a validating recursive resolver; its validator references RFC 4034
(RRSIG/DNSKEY/NSEC/DS), RFC 4035 (validation), RFC 5155 (NSEC3) and RFC 6840
(DNSSEC clarifications). These are converted from <pre> page layout into <p>
paragraphs exactly like prepare_unbound_spec.py does for the core RFCs, and
prefixed with their RFC number for provenance.
"""
import html
import re
import urllib.request
from pathlib import Path

from lxml import html as lhtml

ROOT = Path(__file__).resolve().parents[1]
RFCS = [4034, 4035, 5155, 6840]
out = ROOT / 'output'

PAGE = re.compile(r'^\[Page \d+\]$')
TITLE = re.compile(r'^RFC \d+ .* (19|20)\d{2}\s*$')
NORM = re.compile(r'\b(must not|shall not|should not|may not|must|shall|should|may)\b', re.I)


def normalize(rfc):
    path = out / f'rfc{rfc}.html'
    if not path.exists():
        urllib.request.urlretrieve(f'https://www.rfc-editor.org/rfc/rfc{rfc}.html', path)
    doc = lhtml.parse(str(path))
    lines = []
    for node in doc.xpath('//pre'):
        for line in node.text_content().splitlines():
            stripped = line.strip()
            if PAGE.match(stripped) or TITLE.match(stripped):
                continue
            if stripped in ('Network Working Group', 'Request for Comments'):
                continue
            lines.append(line.rstrip())
    text = '\n'.join(lines)
    paragraphs = [re.sub(r'\n{2,}', '\n', b.strip()) for b in re.split(r'\n\s*\n', text)]
    paragraphs = [p for p in paragraphs if p and len(p) > 8]
    return [f'[RFC {rfc}] ' + NORM.sub(lambda m: m.group(0).upper(), p) for p in paragraphs]


all_paragraphs = []
for rfc in RFCS:
    all_paragraphs.extend(normalize(rfc))
body = '\n'.join('<p>' + html.escape(p) + '</p>' for p in all_paragraphs)
target = out / 'unbound-dnssec-spec.html'
target.write_text('<html><body>\n' + body + '\n</body></html>\n', encoding='utf-8')
counts = {f'RFC{rfc}': sum(1 for p in all_paragraphs if p.startswith(f'[RFC {rfc}]')) for rfc in RFCS}
print({'paragraphs': len(all_paragraphs), 'target': str(target), **counts})
