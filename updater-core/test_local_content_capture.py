"""Cross-platform file-backed capture tests; all input synthetic and caller-owned."""
import dataclasses,hashlib,io,os,tempfile,unittest
from pathlib import Path
from release_core import InvalidRelease,TargetSnapshot
from test_release_core import target as fixture_target
from test_metadata_objects import fixture as blte
from stream_blte import StreamObjectSpec
from local_content_capture import LocalContentCapture,MAX_CAPTURE

def sample(data=b'owned content',mode=b'N'):
 raw,s=blte(data,mode);return raw,StreamObjectSpec(s.ckey,s.ekey,s.decoded_size,s.encoded_size)
class Cases(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.raw,self.spec=sample();self.target=fixture_target()
 def make(self,source=None,spec=None,budget=None):
  return LocalContentCapture.capture(io.BytesIO(self.raw)if source is None else source,target=self.target,spec=self.spec if spec is None else spec,scratch=self.root,byte_budget=len(self.raw)if budget is None else budget)
 def test_verified_independent_copy(self):
  with self.make()as c:r=c.verify();self.assertTrue(r['full_ekey_verified']);self.assertTrue(r['full_ckey_verified']);self.assertTrue(r['copied_content_identity_verified'])
 def test_source_mutated_after_capture_copy_unaffected(self):
  src=io.BytesIO(self.raw)
  with self.make(src)as c:
   src.seek(0);src.write(b'bad');self.assertTrue(c.verify()['full_ckey_verified'])
 def test_source_closed_after_capture_copy_unaffected(self):
  src=io.BytesIO(self.raw)
  with self.make(src)as c:src.close();self.assertTrue(c.verify()['full_ckey_verified'])
 def test_closed_copy_not_verified(self):
  c=self.make();c.close()
  with self.assertRaises(InvalidRelease):c.verify()
 def test_context_closes_and_removes_temp(self):
  with self.make()as c:self.assertFalse(c.closed)
  self.assertTrue(c.closed);self.assertEqual(list(self.root.iterdir()),[])
 def test_corruption_during_capture_rejected(self):
  with self.assertRaises(InvalidRelease):self.make(io.BytesIO(self.raw[:-1]+b'!'))
  self.assertEqual(list(self.root.iterdir()),[])
 def test_partial_capture_rejected(self):
  with self.assertRaises(InvalidRelease):self.make(io.BytesIO(self.raw[:-1]))
 def test_oversized_source_read_rejected(self):
  class Bad:
   def read(s,n):return b'x'*(n+1)
  with self.assertRaises(InvalidRelease):self.make(Bad())
 def test_mutable_source_return_rejected(self):
  class Bad:
   def read(s,n):return bytearray(b'x')
  with self.assertRaises(InvalidRelease):self.make(Bad())
 def test_source_error_cleans_up(self):
  class Bad:
   def read(s,n):raise OSError('synthetic read failure')
  with self.assertRaises(OSError):self.make(Bad())
  self.assertEqual(list(self.root.iterdir()),[])
 def test_copy_corruption_not_admitted(self):
  with self.make()as c:
   c.file.seek(-1,2);c.file.write(b'!');c.file.flush()
   with self.assertRaises(InvalidRelease):c.verify()
 def test_wrong_full_ekey(self):
  with self.assertRaises(InvalidRelease):self.make(spec=dataclasses.replace(self.spec,ekey='f'*32))
 def test_wrong_full_ckey(self):
  with self.assertRaises(InvalidRelease):self.make(spec=dataclasses.replace(self.spec,ckey='f'*32))
 def test_wrong_decoded_size(self):
  with self.assertRaises(InvalidRelease):self.make(spec=dataclasses.replace(self.spec,decoded_size=self.spec.decoded_size+1))
 def test_short_reads_supported(self):
  class Small(io.BytesIO):
   def read(s,n):return super().read(min(n,2))
  with self.make(Small(self.raw))as c:self.assertTrue(c.verify()['full_ckey_verified'])
 def test_exact_budget_no_sentinel_source_read(self):
  class Exact(io.BytesIO):
   def read(s,n):
    if s.tell()>=len(self.raw):raise AssertionError('read beyond grant')
    return super().read(n)
  src=Exact(self.raw+b'not authorized')
  with self.make(src)as c:self.assertEqual(src.tell(),len(self.raw));self.assertEqual(c.source_bytes_read,len(self.raw))
 def test_budget_checked_before_scratch_creation(self):
  with self.assertRaises(InvalidRelease):self.make(budget=len(self.raw)-1)
  self.assertEqual(list(self.root.iterdir()),[])
 def test_boolean_budget_not_authority(self):
  with self.assertRaises(InvalidRelease):self.make(budget=True)
 def test_over_budget_rejected(self):
  with self.assertRaises(InvalidRelease):self.make(budget=MAX_CAPTURE+1)
 def test_target_dict_not_authority(self):
  with self.assertRaises(InvalidRelease):LocalContentCapture.capture(io.BytesIO(self.raw),target=self.target.public(),spec=self.spec,scratch=self.root,byte_budget=100)
 def test_spec_dict_not_authority(self):
  with self.assertRaises(InvalidRelease):LocalContentCapture.capture(io.BytesIO(self.raw),target=self.target,spec=self.spec.public(),scratch=self.root,byte_budget=100)
 def test_no_generation_or_apply_claims(self):
  with self.make()as c:
   r=c.verify()
   for k in ('source_generation_proven','source_store_binding_proven','source_quiescence_proven','source_read_authorized_by_this_api','installed_content_reuse_authorized','required_set_selected','installation_ready','apply_authorized'):self.assertFalse(r[k],k)
   self.assertIsNone(r['required_network_download_bytes']);self.assertIsNone(r['game_access'])
 def test_compressed_stream(self):
  self.raw,self.spec=sample(b'repeat me'*20000,b'Z')
  with self.make()as c:self.assertEqual(c.verify()['decoded_bytes'],180000)
 def test_large_stream_bounded_read(self):
  self.raw,self.spec=sample(bytes(range(256))*6000)
  class Bounded(io.BytesIO):
   def read(s,n):
    assert 0<n<=65536
    return super().read(n)
  with self.make(Bounded(self.raw))as c:self.assertLessEqual(c.verify()['maximum_source_block_bytes'],65536)
if __name__=='__main__':unittest.main()
