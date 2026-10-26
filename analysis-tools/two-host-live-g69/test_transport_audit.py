import unittest,json
from transport_audit import TransportAudit

class T(unittest.TestCase):
    def test_record_fragmentation_every_boundary(self):
        data=b'\x16\x03\x03\x00\x06SECRET'+b'\x17\x03\x03\x00\x03XYZ'
        for split in range(len(data)+1):
            a=TransportAudit();a.feed('private-socket',data[:split]);a.feed('private-socket',data[split:])
            r=a.report()
            self.assertTrue(r['accounting_reconciles'])
            self.assertEqual(r['counts']['TLS_handshake_record_bytes'],11)
            self.assertEqual(r['counts']['TLS_application_data_record_bytes'],8)
            self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('private-socket',json.dumps(r))
            self.assertFalse(r['ciphertext_to_SSPI_plaintext_one_to_one_mapping_proven'])

    def test_HTTP_candidate_is_not_clearance(self):
        a=TransportAudit();a.feed('a',b'GET /SECRET HTTP/1.1\r\n\r\n')
        self.assertEqual(a.report()['counts']['HTTP1_candidate_bytes'],24)
        self.assertTrue(a.report()['accounting_reconciles'])
        self.assertFalse(a.report()['all_processes_and_APIs_covered'])

    def test_close_partial_and_socket_reuse(self):
        a=TransportAudit();a.feed('a',b'\x16\x03');a.close('a')
        a.feed('a',b'GET / HTTP/1.1\r\n\r\n')
        self.assertTrue(a.report()['accounting_reconciles'])
        self.assertEqual(a.report()['counts']['incomplete_at_observed_close_bytes'],2)

    def test_invalid_TLS_is_opaque_not_safe(self):
        a=TransportAudit();a.feed('a',b'\x16\x03\x03\xff\xffSECRET')
        self.assertIn('invalid_TLS_framing_bytes',a.report()['counts'])
        self.assertTrue(a.report()['accounting_reconciles'])

    def test_cap_accounting(self):
        a=TransportAudit();a.total=16777216
        a.feed('a',b'SECRET')
        self.assertTrue(a.report()['cap_hit'])
        # Artificially injected baseline isn't claimed to reconcile.
        self.assertFalse(a.report()['accounting_reconciles'])