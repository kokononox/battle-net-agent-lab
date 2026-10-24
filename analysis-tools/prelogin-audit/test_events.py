import base64
import copy
import json
import unittest
from test_decode import fixture, ld
from decode_startup import wire
from decode_events import analyze, identifier_shapes, extract_all

A = b'11111111-2222-3333-4444-555555555555'
B = b'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def evidence():
    agent, report = fixture()
    request = report['requests'][0]
    raw = base64.b64decode(request['body_sample_base64'])
    context = ld(4, ld(1, A)) + ld(16, B)
    request['body_sample_base64'] = base64.b64encode(ld(1, context) + raw).decode()
    return agent, report


class EventTests(unittest.TestCase):
    def test_decode_and_no_identifier_value_export(self):
        agent, report = evidence()
        result = analyze(agent, report)
        self.assertEqual(result['payload_status_counts'], {'schema_verified': 1})
        self.assertEqual(result['events'][0]['payload_decoding'], 'schema_verified')
        text = json.dumps(result)
        self.assertNotIn(A.decode(), text)
        self.assertNotIn(B.decode(), text)
        self.assertNotIn('PRIVATE FIXTURE CPU', text)
        self.assertFalse(result['context_schema_decoded'])

    def test_in_run_equality_not_persistence(self):
        agent, report = evidence()
        report['requests'].append(copy.deepcopy(report['requests'][0]))
        result = analyze(agent, report)
        slot = next(x for x in result['context_identifier_shapes'] if x['wire_path'] == '/1/4/1')
        self.assertEqual(slot['occurrences'], 2)
        self.assertEqual(slot['distinct_values_within_submitted_report'], 1)
        self.assertEqual(slot['persistence_across_restarts'], 'untested')
        self.assertEqual(slot['hardware_derivation'], 'unverified')

    def test_wrong_image_refused(self):
        agent, report = evidence()
        report['requests'][0]['process_sha256'] = '0' * 64
        result = analyze(agent, report)
        self.assertEqual(result['events'][0]['payload_decoding'], 'image_hash_mismatch')
        self.assertFalse(result['events'][0]['fields_present'])

    def test_unknown_event_marked_not_decoded(self):
        agent, report = evidence()
        request = report['requests'][0]
        original = wire(base64.b64decode(request['body_sample_base64']))
        request['body_sample_base64'] = base64.b64encode(b''.join(ld(n, b'UnknownEvent' if n == 3 else v) for n, w, v in original)).decode()
        result = analyze(agent, report)
        self.assertEqual(result['payload_status_counts'], {'schema_unavailable': 1})
        self.assertFalse(result['events'][0]['fields_present'])

    def test_same_context_uuid_in_unknown_payload(self):
        agent, report = evidence()
        request = report['requests'][0]
        original = wire(base64.b64decode(request['body_sample_base64']))
        rebuilt = []
        for number, kind, value in original:
            if number == 3:
                value = b'UnknownEvent'
            if number == 4:
                value = ld(1, A)
            rebuilt.append(ld(number, value))
        request['body_sample_base64'] = base64.b64encode(b''.join(rebuilt)).decode()
        event = analyze(agent, report)['events'][0]
        self.assertEqual(event['payload_decoding'], 'schema_unavailable')
        self.assertEqual(event['context_uuid_reused_at_payload_wire_paths'], ['/4/1'])
        self.assertNotIn(A.decode(), json.dumps(event))

    def test_no_mutation(self):
        agent, report = evidence()
        before = copy.deepcopy(report)
        analyze(agent, report)
        self.assertEqual(report, before)

    def test_truncated_and_malformed_envelope(self):
        agent, report = evidence()
        report['requests'][0]['body_sample_truncated'] = True
        result = analyze(agent, report)
        self.assertFalse(result['events'])
        self.assertEqual(result['parse_errors'][0]['reason'], 'incomplete_body')
        report['requests'][0]['body_sample_truncated'] = False
        report['requests'][0]['body_sample_base64'] = base64.b64encode(b'\x00').decode()
        self.assertTrue(analyze(agent, report)['parse_errors'])

    def test_non_guid_and_nil_guid_distinction(self):
        self.assertEqual(identifier_shapes(ld(1, b'not a UUID')), [])
        candidate = identifier_shapes(ld(1, b'00000000-0000-0000-0000-000000000000'))
        self.assertEqual(len(candidate), 1)


if __name__ == '__main__':
    unittest.main()
