import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'example' / 'MQTTv5.json'
output = ROOT / 'output' / 'rules_mosquitto_mqtt5.json'
rows = json.loads(source.read_text(encoding='utf-8'))
flattened = [dict(rule) for group in rows.values() for rule in group]
unique = []
seen = set()
for rule in flattened:
    text = rule.get('rule', '').strip()
    if not text or text in seen:
        continue
    seen.add(text)
    unique.append(rule)
output.write_text(json.dumps(unique, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
manifest = {
    'source': 'example/MQTTv5.json',
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'deduplication': 'exact rule text, stable first occurrence',
    'rules': len(unique),
    'specification': 'MQTT Version 5.0, OASIS',
}
(ROOT / 'output' / 'rules_mosquitto_mqtt5.manifest.json').write_text(
    json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(json.dumps(manifest, indent=2))
