"""Write line-addressed source and wire evidence for the paper's four Mosquitto rows."""
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'output/mosquitto-source'
OUT = ROOT / 'output/mosquitto-bug-evidence.json'


def excerpt(relative, start, end):
    path = SOURCE / relative
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    return {
        'file': str(Path('output/mosquitto-source') / relative),
        'start': start,
        'end': end,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'lines': {str(n): lines[n - 1] for n in range(start, end + 1)},
    }


def main():
    data = {
        'scope': 'paper-reported Mosquitto MQTT 5.0 rows; source excerpts are evidence, not automatic bug labels',
        'paper_revision': '849e0f5c583503b87f789ad4ba6ad7f21de0399a',
        'paper_rows': [
            'Missing ShareName Character Validation in sub topic tokenise and sub add',
            'Missing Subscription Identifier Validation in mosquitto property check command',
            'Incorrect QoS for Overlapping Subscriptions in subs send',
            'Incorrect Topic Alias Handling in send real publish',
        ],
        'source_excerpts': {
            'share_name': [excerpt('src/topic_tok.c', 58, 111),
                           excerpt('src/handle_subscribe.c', 99, 109)],
            'subscription_identifier': [excerpt('src/handle_subscribe.c', 82, 90),
                                        excerpt('lib/property_mosq.c', 450, 470)],
            'overlapping_qos': [excerpt('src/subs.c', 45, 105),
                                excerpt('src/subs.c', 110, 151)],
            'topic_alias': [excerpt('src/handle_publish.c', 145, 190),
                            excerpt('lib/send_publish.c', 137, 206)],
        },
        'wire_artifact': 'output/mosquitto-manual-cases.json',
        'wire_status': {
            'share_name_plus': 'rejected with MQTT 5 DISCONNECT 0x81',
            'subscription_identifier_zero': 'rejected with MQTT 5 DISCONNECT 0x81',
            'overlapping_qos_filters_qos2': 'two outgoing PUBLISH packets with QoS [2, 0]; independent discrepancy',
            'topic_alias_max_zero': 'inconclusive; no server-to-client publication created',
        },
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    print(OUT)


if __name__ == '__main__':
    main()
