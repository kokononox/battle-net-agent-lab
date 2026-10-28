import hashlib,json,unittest
import key_diagnostics as d,lookup3
from test_origin_check import prefix
class KeyDiagnostics(unittest.TestCase):
 def setUp(self):self.current=hashlib.md5(b'synthetic-hostdata/data').digest();self.negative=hashlib.md5(b'synthetic-host|bounded-negative-control|data/data').digest()
 def scan(self,raw,archive=0):return d.observe(raw,archive,self.current,self.negative,d.blank())
 def alter(self,callback):
  raw=prefix();out=b''
  for i in range(16):
   h=bytearray(raw[i*30:(i+1)*30]);key=bytearray(h[:16][::-1]);callback(key);h[:16]=key[::-1];h[22:26]=lookup3.hashlittle(h[:22],0x3D6BE971).to_bytes(4,'little');out+=h
  return out
 def test_canonical(self):
  r=self.scan(prefix());o=r['reversed'];self.assertEqual(r['eligible_header_records'],16);self.assertEqual(o['strict_shape_records'],16);self.assertEqual(o['documented_hostname_slice_matches'],16);self.assertEqual(o['negative_hostname_slice_matches'],0);self.assertFalse(r['hostname_marker_proven'])
 def test_tail_only_rejection_isolated(self):
  raw=self.alter(lambda k:k.__setitem__(slice(9,16),bytes([73])*7));r=self.scan(raw);o=r['reversed'];self.assertEqual(o['only_tail_condition_failed'],16);self.assertEqual(o['first9_shape_records'],16);self.assertEqual(o['documented_hostname_slice_matches'],16)
 def test_archive_only_rejection_isolated(self):
  r=self.scan(self.alter(lambda k:k.__setitem__(1,1)));self.assertEqual(r['reversed']['only_archive_condition_failed'],16)
 def test_bucket_only_rejection_isolated(self):
  r=self.scan(self.alter(lambda k:k.__setitem__(0,32)));self.assertEqual(r['reversed']['only_bucket_condition_failed'],16)
 def test_multiple_failed(self):
  def mutate(k):k[0]=32;k[1]=33
  r=self.scan(self.alter(mutate));self.assertEqual(r['reversed']['multiple_conditions_failed'],16)
 def test_position_matrix_does_not_export_values(self):
  r=self.scan(prefix());o=r['reversed'];self.assertEqual(o['bucket_set_at_position_0_to15'][0],1);self.assertEqual(o['filename_archive_at_position_all16'][1],1);self.assertEqual(o['zero_at_position_all16'][9:],[1]*7);text=json.dumps(r);self.assertNotIn('synthetic-host',text);self.assertNotIn(self.current.hex(),text)
 def test_forward_key_order(self):
  raw=prefix();out=b''
  for i in range(16):
   h=bytearray(raw[i*30:(i+1)*30]);h[:16]=h[:16][::-1];h[22:26]=lookup3.hashlittle(h[:22],0x3D6BE971).to_bytes(4,'little');out+=h
  r=self.scan(out);self.assertEqual(r['forward']['strict_shape_records'],16)
 def test_corrupt_checksum_not_eligible(self):
  raw=bytearray(prefix());raw[22]^=1;r=self.scan(bytes(raw));self.assertEqual(r['eligible_header_records'],15);self.assertEqual(r['eligible_complete_first16_blocks'],0)
 def test_all_zero_does_not_create_evidence(self):
  r=self.scan(bytes(480));self.assertEqual(r['eligible_header_records'],0);self.assertEqual(r['reversed']['documented_hostname_slice_matches'],0)
 def test_full_digest_suffix_variant_remains_hint(self):
  r=self.scan(self.alter(lambda k:k.__setitem__(slice(2,16),self.current[2:])));self.assertEqual(r['reversed']['full_hostname_md5_suffix_matches'],16);self.assertFalse(r['marker_acceptance_rules_changed']);self.assertFalse(r['hostname_marker_proven'])
 def test_wrong_hostname_is_not_absence_claim(self):
  r=self.scan(prefix(host='other-host'));self.assertEqual(r['reversed']['strict_shape_records'],16);self.assertEqual(r['reversed']['documented_hostname_slice_matches'],0)
 def test_negative_control_is_separate(self):
  r=self.scan(prefix(host='synthetic-host|bounded-negative-control|'));self.assertEqual(r['reversed']['negative_hostname_slice_matches'],16);self.assertEqual(r['reversed']['documented_hostname_slice_matches'],0)
 def test_bounds_and_schema(self):
  with self.assertRaises(ValueError):self.scan(bytes(65537))
  r=d.blank();r['raw_key']='PRIVATE'
  with self.assertRaises(ValueError):d.validate(r)
 def test_acceptance_rule_not_relaxed(self):
  import origin_check
  raw=self.alter(lambda k:k.__setitem__(slice(9,16),bytes([73])*7));self.assertEqual(origin_check.extract(raw,0),set());self.assertEqual(self.scan(raw)['reversed']['documented_hostname_slice_matches'],16)
if __name__=='__main__':unittest.main()
