import hashlib,json,unittest
import format_diagnostics as d,lookup3
from test_origin_check import prefix
class Diagnostics(unittest.TestCase):
 def setUp(self):
  self.local=hashlib.md5(b'synthetic-hostdata/data').digest()[2:9];self.negative=hashlib.md5(b'synthetic-host|bounded-negative-control|data/data').digest()[2:9]
 def scan(self,raw,archive=0):return d.observe(raw,archive,self.local,self.negative,d.blank())
 def rewrite(self,raw,flags=None,forward=False,zero_seed=False):
  out=b''
  for i in range(16):
   h=bytearray(raw[i*30:(i+1)*30])
   if flags is not None:h[20:22]=flags
   if forward:h[:16]=h[:16][::-1]
   h[22:26]=lookup3.hashlittle(h[:22],0 if zero_seed else 0x3D6BE971).to_bytes(4,'little');out+=h
  return out
 def test_canonical_first16(self):
  r=self.scan(prefix());self.assertEqual(r['records_walked'],16);self.assertEqual(r['checksum_a_seeded_valid'],16);self.assertEqual(r['first16_coherent_reversed_ignoring_flags'],1);self.assertEqual(r['hostname_hint_matches'],16);self.assertEqual(r['negative_control_hint_matches'],0)
 def test_alternative_flags_diagnosed_not_accepted(self):
  import origin_check
  raw=self.rewrite(prefix(),flags=bytes(2));r=self.scan(raw);self.assertEqual(r['flags_0_0'],16);self.assertEqual(r['first16_coherent_reversed_ignoring_flags'],1);self.assertEqual(origin_check.extract(raw,0),set());self.assertFalse(r['marker_acceptance_rules_changed'])
 def test_forward_byte_order_diagnosed(self):
  r=self.scan(self.rewrite(prefix(),forward=True));self.assertEqual(r['first16_coherent_forward_ignoring_flags'],1);self.assertEqual(r['first16_coherent_reversed_ignoring_flags'],0)
 def test_bad_checksum_does_not_support_hint(self):
  raw=bytearray(prefix());raw[22]^=1;r=self.scan(bytes(raw));self.assertEqual(r['checksum_a_seeded_not_verified'],1);self.assertEqual(r['hostname_hint_candidate_records'],15);self.assertEqual(r['first16_coherent_reversed_ignoring_flags'],0)
 def test_zero_seed_distinguished(self):
  r=self.scan(self.rewrite(prefix(),zero_seed=True));self.assertEqual(r['checksum_a_zero_seed_valid'],16);self.assertEqual(r['checksum_a_seeded_valid'],0);self.assertEqual(r['hostname_hint_candidate_records'],0)
 def test_empty_prefix_not_corruption_claim(self):
  r=self.scan(b'');self.assertEqual(r['prefixes_shorter_than_header'],1);self.assertEqual(r['records_walked'],0);self.assertTrue(r['hints_are_not_marker_proof'])
 def test_zero_prefix_diagnosed(self):
  r=self.scan(bytes(480));self.assertEqual(r['prefixes_first480_all_zero'],1);self.assertEqual(r['stopped_invalid_record_span'],1)
 def test_direct_blte_diagnosed(self):self.assertEqual(self.scan(b'BLTE'+bytes(40))['prefixes_begin_blte'],1)
 def test_record_span_beyond_prefix_is_censored(self):
  raw=bytearray(40);raw[16:20]=(1000).to_bytes(4,'little');r=self.scan(bytes(raw));self.assertEqual(r['stopped_record_extends_prefix'],1)
 def test_negative_control_not_marker_proof(self):
  raw=prefix(host='synthetic-host|bounded-negative-control|');r=self.scan(raw);self.assertEqual(r['negative_control_hint_matches'],16);self.assertEqual(r['hostname_hint_matches'],0);self.assertFalse(r['account_identity_proven'])
 def test_raw_identifier_never_in_output(self):
  r=self.scan(prefix());text=json.dumps(r);self.assertNotIn('synthetic-host',text);self.assertNotIn(self.local.hex(),text)
 def test_unrecognized_fields_rejected(self):
  r=d.blank();r['raw_header']='PRIVATE'
  with self.assertRaises(ValueError):d.validate(r)
 def test_prefix_and_record_bounds(self):
  with self.assertRaises(ValueError):self.scan(bytes(65537))
  r=self.scan(prefix()*5);self.assertEqual(r['records_walked'],64);self.assertEqual(r['stopped_record_count_limit'],1)
 def test_duplicate_bucket_indices_reported(self):
  r=self.scan(prefix()[:30]*16);self.assertEqual(r['first16_reversed_duplicate_bucket_indices'],1);self.assertEqual(r['first16_coherent_reversed_ignoring_flags'],0)
if __name__=='__main__':unittest.main()
