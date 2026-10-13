"""Recover compile_commands.json for the Unbound autoconf build from its log."""
import json
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
log = ROOT / 'output' / 'logs' / 'unbound-build.log'
records = []
for line in log.read_text(errors='replace').splitlines():
    if ' -c ' not in line or 'clang-14' not in line:
        continue
    args = shlex.split(line[line.index('clang-14'):])
    args = [a for a in args if not (a in ('>/dev/null', '2>&1', '2>/dev/null', '>&1')
                                    or a.startswith('>') or a.startswith('2>') or a.startswith('&>'))]
    if '-c' not in args:
        continue
    files = [a for a in args if a.endswith('.c') and a != '-c']
    if not files:
        continue
    records.append({'directory': '/workspace/output/unbound-source',
                    'arguments': args, 'file': files[0]})
assert records, 'no compile commands recovered'
out = ROOT / 'output' / 'unbound-compile_commands.json'
out.write_text(json.dumps(records, indent=2))
print(f'recovered {len(records)} compile commands')
