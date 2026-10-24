import base64
import copy
import unittest
from audit_startup import audit


def sample():
    return {'schema': 'bnet-process-birth-http-tls-1', 'reference': {'cpu_model': 'FIXTURE CPU'},
            'processes': [{'pid': 1, 'process_name': 'fixture.exe'}],
            'requests': [{'pid': 1, 'host': 'fixture.invalid', 'method': 'POST', 'target': '/data',
                          'headers': [['user-agent', 'Fixture/1.0']],
                          'body_sample_base64': base64.b64encode(b'FIXTURE CPU').decode(),
                          'body_observed_bytes': 11, 'body_complete': True, 'body_sample_truncated': False}]}


class AuditTests(unittest.TestCase):
    def test_body_match(self):
        result = audit(sample())
        self.assertEqual(result['cpu_literal_hits'][0]['reference_cpu_literal_locations'], ['body_sample'])
        self.assertEqual(result['verdict']['telemetry_domain_is_exclusive_hardware_destination'], 'not_established')

    def test_header_and_target(self):
        data = sample()
        data['requests'][0]['headers'].append(['x-fixture', 'FIXTURE CPU'])
        data['requests'][0]['target'] = '/FIXTURE CPU'
        self.assertEqual(audit(data)['cpu_literal_hits'][0]['reference_cpu_literal_locations'], ['body_sample', 'target', 'header_value'])

    def test_absence_is_not_exclusivity(self):
        data = sample()
        data['requests'][0]['body_sample_base64'] = ''
        data['requests'][0]['body_observed_bytes'] = 0
        result = audit(data)
        self.assertFalse(result['cpu_literal_hits'])
        self.assertEqual(result['verdict']['telemetry_domain_is_exclusive_hardware_destination'], 'not_established')

    def test_invalid_base64_rejected(self):
        data = sample()
        data['requests'][0]['body_sample_base64'] = '!'
        with self.assertRaises(ValueError):
            audit(data)

    def test_empty_reference_rejected(self):
        data = sample()
        data['reference']['cpu_model'] = ''
        with self.assertRaises(ValueError):
            audit(data)

    def test_software_metadata_not_hardware(self):
        result = audit(sample())
        self.assertTrue(result['by_host'][0]['software_version_user_agent_observed'])
        self.assertFalse(result['by_host'][0]['os_label_in_user_agent_observed'])

    def test_raw_values_not_exported(self):
        import json
        data = sample()
        data['requests'][0]['headers'].append(['x-private', 'DO_NOT_EXPORT'])
        text = json.dumps(audit(data))
        self.assertNotIn('DO_NOT_EXPORT', text)
        self.assertNotIn('FIXTURE CPU', text)


if __name__ == '__main__':
    unittest.main()
