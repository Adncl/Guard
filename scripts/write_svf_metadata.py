"""Record SVF-2.9 provenance metadata for a whole-program indirect-call report."""
import hashlib
import json
import sys
from pathlib import Path

ir = Path(sys.argv[1]).resolve()
meta = {
    'tool': 'SVF', 'tag': 'SVF-2.9',
    'command': ['wpa', '-print-fp', '-ander', 'unbound.bc'],
    'raw_report': 'fp.txt', 'parsed_report': 'ffp.txt',
    'raw_report_sha256': hashlib.sha256((ir / 'fp.txt').read_bytes()).hexdigest(),
    'parsed_report_sha256': hashlib.sha256((ir / 'ffp.txt').read_bytes()).hexdigest(),
    'parsed_records': sum(1 for l in (ir / 'ffp.txt').read_text().splitlines() if l.strip()),
}
(ir / 'svf_metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps(meta, indent=2))
