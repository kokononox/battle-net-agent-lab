import dataclasses,hashlib,unittest
from local_candidates import LocalRef
from test_local_candidates import fixture
from paired_prefix import verify_paired_zero_prefix
from release_core import InvalidRelease
class Tests(unittest.TestCase):
 def setUp(self):
  _,raw,self.spec,ref,_=fixture();self.p=LocalRef(ref.prefix,3,700,len(raw)+30,0);self.d=LocalRef(ref.prefix,3,730,len(raw),1);self.raw=bytes(30)+raw
  def row(r):return r.prefix+((r.archive_id<<30)|r.offset).to_bytes(5,'big')+r.span.to_bytes(4,'little')
  self.idx=bytes(40)+row(self.p)+row(self.d);self.sha=hashlib.sha256(self.idx).hexdigest()
 def verify(self,**kw):
  a=dict(index_raw=self.idx,index_sha256=self.sha,prefix_ref=self.p,direct_ref=self.d,archive_bytes=10000,raw=self.raw,spec=self.spec);a.update(kw);return verify_paired_zero_prefix(**a)
 def test_zero_prefix_valid(self):
  r=self.verify();self.assertTrue(r['full_ckey_verified']);self.assertTrue(r['zero_prefix_observed'])
  for k in ('reuse_authorized','native_archive_header_validity_proven','general_archive_header_policy_proven','fresh_live_state_proven','installation_ready','apply_authorized'):self.assertFalse(r[k])
 def test_wrong_index_hash(self):
  with self.assertRaises(InvalidRelease):self.verify(index_sha256='0'*64)
 def test_wrong_row(self):
  with self.assertRaises(InvalidRelease):self.verify(direct_ref=dataclasses.replace(self.d,ordinal=0))
 def test_relation_mismatch(self):
  for r in (dataclasses.replace(self.d,offset=731),dataclasses.replace(self.d,archive_id=4),dataclasses.replace(self.d,span=self.d.span+1)):
   with self.assertRaises(InvalidRelease):self.verify(direct_ref=r)
 def test_nonzero_prefix(self):
  with self.assertRaises(InvalidRelease):self.verify(raw=b'x'+self.raw[1:])
 def test_corrupt_body(self):
  with self.assertRaises(InvalidRelease):self.verify(raw=self.raw[:-1]+bytes([self.raw[-1]^1]))
 def test_out_of_bounds(self):
  with self.assertRaises(InvalidRelease):self.verify(archive_bytes=730)
 def test_short_span(self):
  with self.assertRaises(InvalidRelease):self.verify(raw=self.raw[1:])
if __name__=='__main__':unittest.main()
