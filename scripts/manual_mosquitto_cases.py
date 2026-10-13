import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protocolguard.common import load_config
from protocolguard.verification import (canonical_mqtt5_positive_payload, mqtt_frames,
                                         protocol_adapter, replay)


def vbi(value):
    out = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 128
        out.append(digit)
        if not value:
            return bytes(out)


def string(value):
    data = value.encode()
    return len(data).to_bytes(2, 'big') + data


def connect(client='pgmanual', properties=b''):
    body = b'\x00\x04MQTT\x05\x02\x00\x3c' + vbi(len(properties)) + properties + string(client)
    return b'\x10' + vbi(len(body)) + body


def subscribe(packet_id, topic, options=0, properties=b''):
    body = packet_id.to_bytes(2, 'big') + vbi(len(properties)) + properties + string(topic) + bytes([options])
    return b'\x82' + vbi(len(body)) + body


def publish(topic, payload=b'x', properties=b''):
    body = string(topic) + vbi(len(properties)) + properties + payload
    return b'\x30' + vbi(len(body)) + body


def publish_qos2(topic, packet_id=7, payload=b'x', properties=b''):
    body = string(topic) + packet_id.to_bytes(2, 'big') + vbi(len(properties)) + properties + payload
    return b'\x34' + vbi(len(body)) + body


def pubrel(packet_id=7):
    return b'\x62\x02' + packet_id.to_bytes(2, 'big')


def summarize(result):
    response_frames = mqtt_frames(bytes.fromhex(result['response_hex']))
    publish_qos = [((header >> 1) & 3) for header, _ in response_frames
                   if (header >> 4) == 3]
    disconnect_reasons = [body[0] for header, body in response_frames
                          if (header >> 4) == 14 and body]
    return {
        'payload_hex': result['payload_hex'],
        'response_hex': result['response_hex'],
        'input_types': [h >> 4 for h, _ in mqtt_frames(bytes.fromhex(result['payload_hex']))],
        'response_types': [h >> 4 for h, _ in mqtt_frames(bytes.fromhex(result['response_hex']))],
        'response_publish_qos': publish_qos,
        'disconnect_reason_codes': disconnect_reasons,
        'returncode_before_cleanup': result['returncode_before_cleanup'],
        'stderr_tail': result['stderr'][-1200:],
    }


def main():
    config = load_config(ROOT / 'config/mosquitto.toml')
    adapter = protocol_adapter(config)
    cases = {
        'positive': canonical_mqtt5_positive_payload(),
        # MQTT-4.8.2-2: '+' is forbidden inside the ShareName.
        'share_name_plus': connect() + subscribe(1, '$share/foo+/temperature'),
        # MQTT-3.3.1/Subscription Identifier: value zero is a Protocol Error.
        'subscription_identifier_zero': connect() + subscribe(1, 'temperature', properties=b'\x0b\x00'),
        # MQTT-3.3.4-2: overlapping subscriptions should use maximum granted QoS.
        'overlapping_qos': (connect() + subscribe(1, 'overlap', 0) +
                            subscribe(2, 'overlap', 2) + publish('overlap')),
        # Two distinct filters both match the same publication.  This avoids
        # the broker's same-filter update path and exercises subs__send twice.
        'overlapping_qos_filters': (connect() + subscribe(1, 'overlap/#', 0) +
                                    subscribe(2, 'overlap/leaf', 2) +
                                    publish('overlap/leaf', properties=b'', payload=b'x')),
        'overlapping_qos_filters_qos2': (connect() + subscribe(1, 'overlap/#', 0) +
                                         subscribe(2, 'overlap/leaf', 2) +
                                         publish_qos2('overlap/leaf') + pubrel()),
        # MQTT-3.1.2-27/3.3.2: a client advertising alias maximum zero must not
        # receive a server PUBLISH with a Topic Alias.
        'topic_alias_max_zero': (connect(properties=b'\x22\x00\x00') +
                                 publish('alias-topic', properties=b'\x23\x00\x01')),
    }
    out = {}
    for name, payload in cases.items():
        result = replay(adapter['binary'], payload, ROOT / 'output/mosquitto-manual-cases',
                        name + '-baseline', adapter)
        out[name] = summarize(result)
        if name in ('share_name_plus', 'subscription_identifier_zero'):
            out[name]['wire_interpretation'] = 'expected MQTT 5 protocol rejection; observed DISCONNECT 0x81'
        elif name == 'overlapping_qos_filters_qos2':
            out[name]['wire_interpretation'] = ('independent discrepancy: two distinct matching filters with requested QoS 0 and 2 '
                                                 'produced two outgoing PUBLISH packets with QoS [2, 0], rather than one '
                                                 'publication at the maximum matching QoS')
        elif name == 'overlapping_qos':
            out[name]['wire_interpretation'] = 'non-decisive control: same-filter resubscription updates one subscription'
        elif name == 'overlapping_qos_filters':
            out[name]['wire_interpretation'] = 'non-decisive control: incoming QoS 0 caps both deliveries at QoS 0'
        elif name == 'topic_alias_max_zero':
            out[name]['wire_interpretation'] = 'probe incomplete: no server-to-client publication was created'
        elif name == 'positive':
            out[name]['wire_interpretation'] = 'positive MQTT 5 control: CONNACK Success followed by PINGRESP'
        print(name, out[name]['response_types'], out[name]['response_hex'])
    path = ROOT / 'output/mosquitto-manual-cases.json'
    path.write_text(json.dumps({'scope': 'independent MQTT 5 wire replay; no LLM conclusion or assertion',
                                'cases': out}, indent=2) + '\n')
    print(path)


if __name__ == '__main__':
    main()
