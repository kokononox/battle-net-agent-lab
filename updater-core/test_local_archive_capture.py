import dataclasses,io,struct,tempfile,unittest
from pathlib import Path
from release_core import InvalidRelease
from test_local_content_capture import sample
from test_release_core import target
from local_archive_capture import ArchiveReadRequest,capture_archive_stream
from lookup3 import hashlittle2
from local_spans import span_checksum_b

def archive_fixture(raw,spec,archive_id=3,offset=700):
 h=bytes.fromhex(spec.ekey)[::-1]+struct.pack('<I',len(raw)+30)+bytes(2)
 h+=hashlittle2(h,0x3D6BE971)[0].to_bytes(4,'little');h+=span_checksum_b(h,archive_id,offset)
 return b'X'*offset+h+raw+b'not-authorized-trailer'
class Cases(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.raw,self.spec=sample();self.req=ArchiveReadRequest(target(),self.spec,3,700,'prefix30-agent9824',30+len(self.raw));self.archive=archive_fixture(self.raw,self.spec)
 def run_capture(self,data=None,req=None,stream=None,size=None):
  data=self.archive if data is None else data;req=self.req if req is None else req
  return capture_archive_stream(io.BytesIO(data)if stream is None else stream,archive_size=len(data)if size is None else size,request=req,scratch=self.root)
 def test_prefix_full_identity_and_exact_budget(self):
  c,r=self.run_capture()
  with c:self.assertTrue(c.verify()['full_ckey_verified']);self.assertEqual(r['archive_application_content_bytes_read'],len(self.raw)+30);self.assertTrue(r['header_checksums_verified'])
 def test_direct_layout_explicit_no_header_guess(self):
  q=dataclasses.replace(self.req,layout='direct-blte',byte_budget=len(self.raw));c,r=self.run_capture(data=b'x'*700+self.raw,req=q)
  with c:self.assertEqual(r['header_bytes_read'],0);self.assertFalse(r['automatic_fallback_used'])
 def test_absolute_reads_never_outside_span(self):
  request=self.req
  class Guard(io.BytesIO):
   def read(s,n):
    assert request.offset<=s.tell()<request.offset+request.span
    assert 0<n<=min(65536,request.offset+request.span-s.tell())
    return super().read(n)
  src=Guard(self.archive);c,r=self.run_capture(stream=src)
  with c:self.assertEqual(src.tell(),self.req.offset+self.req.span)
 def test_short_source_reads(self):
  class Small(io.BytesIO):
   def read(s,n):return super().read(min(n,2))
  c,r=self.run_capture(stream=Small(self.archive))
  with c:self.assertTrue(c.verify()['full_ckey_verified'])
 def bad(self,data=None,req=None,size=None):
  with self.assertRaises(InvalidRelease):self.run_capture(data=data,req=req,size=size)
 def test_bad_header_key_no_fallback(self):
  a=bytearray(self.archive);a[700]^=1;self.bad(bytes(a));self.assertEqual(list(self.root.iterdir()),[])
 def test_bad_header_checksum_a(self):
  a=bytearray(self.archive);a[722]^=1;self.bad(bytes(a))
 def test_bad_header_checksum_b(self):
  a=bytearray(self.archive);a[726]^=1;self.bad(bytes(a))
 def test_bad_header_size(self):
  a=bytearray(self.archive);a[716]^=1;self.bad(bytes(a))
 def test_unsupported_flags(self):
  a=bytearray(self.archive);a[720]=1;self.bad(bytes(a))
 def test_bad_payload(self):
  a=bytearray(self.archive);a[730+len(self.raw)-1]^=1;self.bad(bytes(a));self.assertEqual(list(self.root.iterdir()),[])
 def test_source_bounds_checked_before_read(self):
  class Never:
   def seek(s,n):raise AssertionError('unexpected source access')
  with self.assertRaises(InvalidRelease):self.run_capture(stream=Never(),size=701)
 def test_header_truncated_despite_wrong_stat(self):self.bad(data=self.archive[:710],size=len(self.archive))
 def test_payload_truncated_despite_wrong_stat(self):self.bad(data=self.archive[:730+len(self.raw)-1],size=len(self.archive))
 def test_wrong_layout_not_autodetected(self):
  q=dataclasses.replace(self.req,layout='direct-blte',byte_budget=len(self.raw));self.bad(req=q)
 def test_archive_id_bound_checksum(self):self.bad(req=dataclasses.replace(self.req,archive_id=4))
 def test_offset_bound_checksum(self):
  # Same header moved by a byte: embedded location checksum must fail.
  self.bad(data=b'X'+self.archive,req=dataclasses.replace(self.req,offset=701))
 def test_invalid_request_budgets(self):
  for k,v in [('archive_id',True),('archive_id',1000),('offset',-1),('offset',True),('layout','auto'),('byte_budget',True),('byte_budget',self.req.span+1),('offset',(1<<30)-1)]:
   with self.subTest(field=k,value=v):
    with self.assertRaises(InvalidRelease):dataclasses.replace(self.req,**{k:v})
 def test_dict_not_authority(self):
  with self.assertRaises(InvalidRelease):capture_archive_stream(object(),archive_size=999,request={},scratch=self.root)
 def test_source_can_close_independent_copy_remains(self):
  src=io.BytesIO(self.archive);c,r=self.run_capture(stream=src);src.close()
  with c:self.assertTrue(c.verify()['full_ckey_verified'])
 def test_report_no_installation_authority(self):
  c,r=self.run_capture()
  with c:
   for k in ('source_generation_proven','source_store_binding_proven','source_read_approval_implied','required_set_selected','installed_content_reuse_authorized','installation_ready','apply_authorized'):self.assertFalse(r[k],k)
   self.assertIsNone(r['required_network_download_bytes']);self.assertEqual(r['source_stream_bytes_outside_requested_span'],0)
if __name__=='__main__':unittest.main()
