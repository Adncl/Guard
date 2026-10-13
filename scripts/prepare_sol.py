"""Create a clean, repeatable Sol experiment from the supplied archive."""
from pathlib import Path
import hashlib
import json
import re
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / 'output'
out.mkdir(exist_ok=True)
source = out / 'sol-source'
manifest = {'archive_sha256': hashlib.sha256((ROOT / 'example/sol.tar.gz').read_bytes()).hexdigest(), 'removed_assertion_blocks': {}}
if source.exists():
    import shutil
    shutil.rmtree(source)
with tarfile.open(ROOT / 'example/sol.tar.gz') as archive:
    for member in archive:
        relative = Path(member.name).relative_to('sol')
        if not member.isfile() or any(part in ('build', '.git') for part in relative.parts):
            continue
        path = (source / relative).resolve()
        if not path.is_relative_to(source.resolve()):
            raise ValueError('Unsafe archive path')
        data = archive.extractfile(member).read()
        if path.suffix in ('.c', '.h'):
            text, count = re.subn(r'(?ms)^\s*#ifdef ASSERT_ENABLED\b.*?^\s*#endif[^\n]*\n?', '', data.decode())
            if count:
                manifest['removed_assertion_blocks'][str(relative)] = count
            data = text.encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
html = out / 'mqtt-v3.1.1.html'
url = 'https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html'
if not html.exists():
    with urllib.request.urlopen(url, timeout=60) as response:
        html.write_bytes(response.read())
manifest['specification_url'] = url
manifest['specification_sha256'] = hashlib.sha256(html.read_bytes()).hexdigest()
(out / 'source_manifest.json').write_text(json.dumps(manifest, indent=2))
print('Prepared original uninstrumented Sol source and MQTT 3.1.1 specification')
