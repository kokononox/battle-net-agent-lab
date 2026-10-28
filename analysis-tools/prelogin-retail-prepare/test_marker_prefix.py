import unittest
import marker_prefix as m
import test_poststop_content as fixtures
class Prefix(unittest.TestCase):
 def fixture(self):
  import hashlib
  self.seed=hashlib.md5(b'synthetic-download-hostdata/data').digest()[2:9];self.negative=bytes([self.seed[0]^1])+self.seed[1:];self.r=m.blank();self.r.update(prediction_bound_before_form_post=True,local_hostname_prediction_unchanged=True);return fixtures.Markers().prefix()
 def test_nonzero_offset_and_untrusted_filename_not_needed(self):
  raw=self.fixture();m.scan(b'padding'*11+raw+b'junk',self.seed,self.negative,self.r);self.assertTrue(self.r['host_related_container_marker_observed']);self.assertEqual(self.r['matching_blocks'],1)
 def test_near_end_partial_not_proof(self):
  raw=self.fixture();m.scan(raw[:-1],self.seed,self.negative,self.r);self.assertFalse(self.r['host_related_container_marker_observed'])
 def test_private_seed_alone_not_proof(self):
  self.fixture();m.scan(bytes(7)+self.seed[::-1]+bytes(1000),self.seed,self.negative,self.r);self.assertFalse(self.r['host_related_container_marker_observed'])
 def test_bad_checksum_not_proof(self):
  raw=bytearray(self.fixture());raw[22]^=1;m.scan(bytes(raw),self.seed,self.negative,self.r);self.assertFalse(self.r['host_related_container_marker_observed'])
 def test_negative_hostname_block_prevents_positive(self):
  raw=self.fixture();other=fixtures.Markers().prefix(seed=self.negative);m.scan(raw+other,self.seed,self.negative,self.r);self.assertEqual(self.r['negative_control_blocks'],1);self.assertFalse(self.r['host_related_container_marker_observed'])
 def test_read_bound(self):
  self.fixture()
  with self.assertRaises(ValueError):m.scan(bytes(m.MAX_PREFIX+1),self.seed,self.negative,self.r)
 def test_candidate_bound(self):
  self.fixture();self.r['candidate_blocks_checked']=64
  with self.assertRaises(ValueError):m.scan(bytes(7)+self.seed[::-1]+bytes(500),self.seed,self.negative,self.r)
 def test_no_identifier_export(self):
  r=m.blank();r['hash']='PRIVATE'
  with self.assertRaises(ValueError):m.validate(r)
if __name__=='__main__':unittest.main()
