"""Normalize the HTMLized RFC 1035 into paragraph HTML for rule extraction.

The 1987 RFC predates RFC 2119 capitalization and the rfc-editor HTML renders
the text inside <pre> blocks, while the extraction module expects paragraph
(<p>) input with uppercase normative keywords. This preprocessor:
- concatenates <pre> content in document order,
- drops page headers/footers,
- wraps blank-line-separated blocks into <p> paragraphs,
- upper-cases must/shall/should/may into MUST/SHALL/SHOULD/MAY.
"""
import html
import io
import re
from pathlib import Path

from lxml import html as lhtml

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'output' / 'rfc1035.html'
target = ROOT / 'output' / 'rfc1035-normalized.html'

doc = lhtml.parse(str(source))
blocks = []
for node in doc.xpath('//pre'):
    text = node.text_content()
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[Page \d+\]$', stripped):
            continue
        if re.match(r'^RFC 1035\s+.*1987$', stripped):
            continue
        if re.match(r'^Mockapetris\s*\[Page \d+\]$', stripped):
            continue
        if stripped == 'Network Working Group':
            continue
        lines.append(line.rstrip())
    blocks.append('\n'.join(lines))
text = '\n'.join(blocks)
paragraphs = [re.sub(r'\n{2,}', '\n', block.strip()) for block in re.split(r'\n\s*\n', text)]
paragraphs = [p for p in paragraphs if p]
def uppercase_normative(text):
    def repl(match):
        return match.group(0).upper()
    return re.sub(r'\b(must not|shall not|should not|may not|must|shall|should|may)\b',
                  repl, text, flags=re.I)
body = '\n'.join('<p>' + html.escape(uppercase_normative(p)) + '</p>' for p in paragraphs)
target.write_text('<html><body>\n' + body + '\n</body></html>\n', encoding='utf-8')
counts = {word: len(re.findall(r'\b' + word.upper() + r'\b', body))
          for word in ['MUST', 'SHALL', 'SHOULD', 'MAY']}
print({'paragraphs': len(paragraphs), 'target': str(target), **counts})
