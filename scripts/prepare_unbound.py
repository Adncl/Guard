"""Download and prepare the latest Unbound release for ProtocolGuard analysis."""
import hashlib
import json
import re
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / 'output'
out.mkdir(exist_ok=True)
VERSION = '1.26.0'
url = f'https://nlnetlabs.nl/downloads/unbound/unbound-{VERSION}.tar.gz'
archive = out / 'vendor' / f'unbound-{VERSION}.tar.gz'
archive.parent.mkdir(parents=True, exist_ok=True)
if not archive.exists():
    urllib.request.urlretrieve(url, archive)
source = out / 'unbound-source'
if not (source / 'configure').is_file():
    if source.exists():
        import shutil
        shutil.rmtree(source)
    with tarfile.open(archive) as tar:
        for member in tar:
            relative = Path(member.name).relative_to(f'unbound-{VERSION}')
            if not member.isfile() or any(part in ('.git',) for part in relative.parts):
                continue
            path = (source / relative).resolve()
            if not path.is_relative_to(source.resolve()):
                raise ValueError('Unsafe archive path')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(tar.extractfile(member).read())
spec = out / 'rfc1035.html'
spec_url = 'https://www.rfc-editor.org/rfc/rfc1035.html'
if not spec.exists():
    with urllib.request.urlopen(spec_url, timeout=60) as response:
        spec.write_bytes(response.read())
dissector_dir = ROOT / 'rule_extraction' / 'documentProcess' / 'directoryStore'
dissector = dissector_dir / 'packet-dns.c'
if not dissector.exists():
    urllib.request.urlretrieve(
        'https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-dns.c',
        dissector)
manifest = {
    'version': VERSION,
    'url': url,
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'specification': 'RFC 1035 (Domains Implementation and Specification)',
    'specification_url': spec_url,
    'specification_sha256': hashlib.sha256(spec.read_bytes()).hexdigest(),
    'dissector': 'Wireshark packet-dns.c',
    'dissector_sha256': hashlib.sha256(dissector.read_bytes()).hexdigest(),
}
(out / 'unbound_source_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
