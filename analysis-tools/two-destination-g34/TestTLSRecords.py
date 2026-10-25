import json,ssl,struct,unittest
from tls_records import TLSMetadata,validate_summary

def record(k,b):return struct.pack('!BBBH',k,3,3,len(b))+b
def handshake(k,b):return bytes([k])+len(b).to_bytes(3,'big')+b
class Tests(unittest.TestCase):
 def test_client_hello_no_sni_export(self):
  incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();obj=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname='us.version.battle.net')
  try:obj.do_handshake()
  except ssl.SSLWantReadError:pass
  t=TLSMetadata();t.feed('client',outgoing.read());r=validate_summary(t.summary());self.assertIn('client_hello',r['client']['handshake_types']);self.assertNotIn('battle.net',json.dumps(r))
 def test_fragmented_record_header(self):
  t=TLSMetadata();b=record(21,b'\x02\x30')
  for x in b:t.feed('client',bytes([x]))
  r=t.summary()['client'];self.assertEqual(r['cleartext_alerts'],[{'level':2,'description':48}]);self.assertEqual(r['partial_record_bytes'],0)
 def test_encrypted_outer_application_data_not_decoded(self):
  t=TLSMetadata();t.feed('client',record(23,b'SECRET_PASSWORD_TOKEN'));r=validate_summary(t.summary());self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['client']['cleartext_alerts'],[])
 def test_tls12_encrypted_alert_not_decoded(self):
  t=TLSMetadata();t.feed('server',record(20,b'\x01')+record(21,b'\x02\x30'));self.assertEqual(t.summary()['server']['cleartext_alerts'],[])
 def test_selected_version_server_hello(self):
  body=b'\x03\x03'+bytes(32)+b'\x00\x13\x01\x00'+b'\x00\x06\x00\x2b\x00\x02\x03\x04';wire=handshake(2,body);t=TLSMetadata();t.feed('server',record(22,wire));s=validate_summary(t.summary())['server'];self.assertEqual(s['selected_version'],'tls13');self.assertEqual(s['selected_cipher'],0x1301)
 def test_fragmented_handshake(self):
  wire=handshake(11,b'PRIVATE_CERT_BYTES');t=TLSMetadata();t.feed('server',record(22,wire[:7]));t.feed('server',record(22,wire[7:]));r=validate_summary(t.summary());self.assertEqual(r['server']['handshake_types'],['certificate']);self.assertNotIn('PRIVATE',json.dumps(r))
 def test_record_limit(self):
  t=TLSMetadata();t.feed('client',record(23,b'x')*40);s=validate_summary(t.summary())['client'];self.assertEqual(len(s['records']),32);self.assertTrue(s['truncated'])
 def test_invalid_framing_not_traffic_decision(self):
  t=TLSMetadata();t.feed('server',b'HTTP/1.1 200 OK\r\n');self.assertTrue(t.summary()['server']['invalid_framing'])
 def test_partial_record_not_complete(self):
  t=TLSMetadata();t.feed('client',record(23,b'abcdef')[:-1]);self.assertGreater(t.summary()['client']['partial_record_bytes'],0);self.assertEqual(t.summary()['client']['records'],[])
 def test_bounded_huge_handshake(self):
  t=TLSMetadata();t.feed('server',record(22,b'\x0b\xff\xff\xff'));self.assertTrue(t.summary()['server']['truncated'])
 def test_schema_rejects_payload(self):
  r=TLSMetadata().summary();r['server']['raw']='SECRET'
  with self.assertRaises(ValueError):validate_summary(r)
if __name__=='__main__':unittest.main()
