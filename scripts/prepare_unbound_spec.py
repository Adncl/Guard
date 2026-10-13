"""Download and normalize the core RFCs that Unbound 1.26.0 implements.

Unbound is a recursive DNS resolver; its source and docs reference a large
RFC set. The rules extracted for consistency testing cover the core wire-
behavior specifications the implementation actually claims:

  RFC 1035  Domain Names - Implementation and Specification
  RFC 2181  Clarifications to the DNS Specification
  RFC 4343  DNS Case Insensitivity Clarification
  RFC 2308  Negative Caching of DNS Queries
  RFC 1982  Serial Number Arithmetic for Implementing DNS

Each HTMLized RFC is converted from <pre> page layout into <p> paragraphs,
page headers/footers are dropped, normative keywords are upper-cased, and
every paragraph is prefixed with its RFC number for provenance. The result
is a single combined specification consumed by protocolguard.extraction.
"""
import html
import re
import urllib.request
from pathlib import Path

from lxml import html as lhtml

ROOT = Path(__file__).resolve().parents[1]
RFCS = [1035, 2181, 4343, 2308, 1982]
out = ROOT / 'output'
out.mkdir(exist_ok=True)

PAGE = re.compile(r'^\[Page \d+\]$')
TITLE = re.compile(r'^RFC \d+ .* (19|20)\d{2}\s*$')
STATUS = re.compile(r'\b(Standards Track|Informational|Experimental|Best Current Practice|'
                    r'Proposed Standard|Historic|Internet Standard)\b')
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
    result = []
    for p in paragraphs:
        normalized = NORM.sub(lambda m: m.group(0).upper(), p)
        result.append(f'[RFC {rfc}] {normalized}')
    return result


all_paragraphs = []
for rfc in RFCS:
    all_paragraphs.extend(normalize(rfc))

body = '\n'.join('<p>' + html.escape(p) + '</p>' for p in all_paragraphs)
target = out / 'unbound-spec.html'
target.write_text('<html><body>\n' + body + '\n</body></html>\n', encoding='utf-8')
counts = {f'RFC{rfc}': sum(1 for p in all_paragraphs if p.startswith(f'[RFC {rfc}]')) for rfc in RFCS}
print(json := {'paragraphs': len(all_paragraphs), 'target': str(target), **counts})
