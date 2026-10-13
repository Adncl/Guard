from pathlib import Path
import tempfile
import unittest
from protocolguard.common import parse_json
from protocolguard.detection import validate_report
from protocolguard.slicing import reachable
from protocolguard.slicing import source_functions
from protocolguard.verification import (apply_edits, canonical_positive_payload,
                                         canonical_mqtt5_positive_payload, mqtt_frames,
                                         positive_control_ok, protocol_adapter,
                                         baseline_witness)
from protocolguard.packets import extract_payload

class AnalysisTests(unittest.TestCase):
    def test_source_uses_definition_instead_of_forward_declaration(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.c'
            path.write_text('int f(int);\n\nint f(int x) {\n return x;\n}\n')
            path.with_name('.cf_a.json').write_text(json.dumps({'functions': [
                {'name': 'f', 'overall': {'start': 1, 'end': 1}, 'body': {'start': 3, 'end': 5}},
                {'name': 'f', 'overall': {'start': 3, 'end': 5}, 'body': {'start': 3, 'end': 5}}]}))
            f = source_functions({'functions': {'f': {'file': str(path), 'start': 3, 'end': 4}}})['f']
            self.assertEqual(f['start'], 3)
            self.assertIn('return x', f['lines'][4])

    def test_cyclic_def_use_reaches_transitive_dependents(self):
        self.assertEqual(reachable({1: [2], 2: [3], 3: [1, 4]}, [1]), {1, 2, 3, 4})

    def test_json_with_reasoning_and_code_fences(self):
        self.assertEqual(parse_json('<think>{not JSON}</think>```json\n{"ok":true}\n```'), {'ok': True})

    def test_hallucinated_violation_lines_are_rejected(self):
        report = {'result': 'violation found!', 'reason': 'Missing validation', 'violations': [
            {'function_name': 'parse', 'filename': '/a.c', 'code_lines': [99]}]}
        code = 'Function: parse\nPath: /a.c:1\n      1  int parse() {}'
        with self.assertRaises(ValueError):
            validate_report(report, code)
        report['violations'][0]['code_lines'] = [1]
        validate_report(report, code)

    def test_assertion_patch_does_not_change_normal_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'a.c'
            path.write_text('void f(int x) {\n use(x);\n}\n')
            with self.assertRaises(ValueError):
                apply_edits(root, [{'file': 'a.c', 'before': ' use(x);', 'after': ' if(x) use(x);'}])
            apply_edits(root, [{'file': 'a.c', 'before': ' use(x);',
                'after': '#ifdef ASSERT_ENABLED\n assert(x);\n#endif\n use(x);'}])
            self.assertIn('assert(x)', path.read_text())

    def test_assertion_edit_cannot_escape_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                apply_edits(Path(tmp), [{'file': '../escape.c', 'before': 'x', 'after': 'y'}])

class PacketTests(unittest.TestCase):
    def test_canonical_positive_is_two_valid_mqtt_frames(self):
        self.assertEqual([h for h, _ in mqtt_frames(canonical_positive_payload())], [0x10, 0xc0])

    def test_mqtt5_positive_has_v5_connect_and_pingreq(self):
        frames = mqtt_frames(canonical_mqtt5_positive_payload())
        self.assertEqual([h for h, _ in frames], [0x10, 0xc0])
        self.assertEqual(frames[0][1][6], 5)

    def test_mosquitto_positive_oracle_accepts_properties(self):
        adapter = protocol_adapter({'project': {
            'project_name': 'Mosquitto', 'protocol_name': 'MQTT', 'protocol_version': '5.0'}})
        result = {'returncode_before_cleanup': None, 'assertion_failure': False,
                  'response_hex': '200900000622000a210014d000'}
        self.assertTrue(positive_control_ok(result, adapter))

    def test_mosquitto_overlapping_filter_wire_witness(self):
        adapter = protocol_adapter({'project': {
            'project_name': 'Mosquitto', 'protocol_name': 'MQTT', 'protocol_version': '5.0'}})
        result = {
            'returncode_before_cleanup': None,
            'payload_hex': ('101500044d5154540502003c00000870676d616e75616c820f00010000096f7665726c61702f23008212000200000c6f7665726c61702f6c656166023412000c6f7665726c61702f6c6561660007007862020007'),
            'response_hex': ('200900000622000a210014900400010000900400020002500200073412000c6f7665726c61702f6c656166000100783010000c6f7665726c61702f6c656166007870020007'),
        }
        self.assertTrue(baseline_witness('Incorrect QoS for Overlapping Subscriptions', result, adapter))

    def capture(self, packets):
        from scapy.all import wrpcap
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'test.pcap'
        wrpcap(str(path), packets)
        return path

    def test_reassembly_deduplicates_and_orders_segments(self):
        from scapy.all import IP, TCP, Raw
        def p(seq, data):
            return IP(src='127.0.0.1', dst='127.0.0.2')/TCP(sport=10000, dport=1883, seq=seq)/Raw(data)
        path = self.capture([p(102, b'cd'), p(100, b'ab'), p(100, b'ab'), p(103, b'def')])
        self.assertEqual(extract_payload(path, 1883), b'abcdef')

    def test_gaps_and_conflicting_retransmissions_fail(self):
        from scapy.all import IP, TCP, Raw
        def p(seq, data):
            return IP()/TCP(sport=10000, dport=1883, seq=seq)/Raw(data)
        for packets in ([p(1, b'ab'), p(8, b'cd')], [p(1, b'ab'), p(1, b'ac')]):
            with self.assertRaises(ValueError):
                extract_payload(self.capture(packets), 1883)

    def test_multiple_sessions_not_concatenated(self):
        from scapy.all import IP, TCP, Raw
        path = self.capture([IP()/TCP(sport=1, dport=1883)/Raw(b'a'), IP()/TCP(sport=2, dport=1883)/Raw(b'b')])
        with self.assertRaises(ValueError):
            extract_payload(path, 1883)

if __name__ == '__main__':
    unittest.main()
