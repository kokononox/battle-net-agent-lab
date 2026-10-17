import json,os,random,struct,tempfile,unittest
from pathlib import Path
import agent_archive_io as io
import patch_audit as a
import source_binding as b
import synthetic_casc_format as fmt
O=Path(os.environ.get('ARCHIVE_IO_ORACLE','/missing'));S=Path(os.environ.get('SPAN_READER_ORACLE','/missing'));P=Path(os.environ.get('SPAN_PRIOR_STORE','/missing'))
K='914fcad4f4fcf4abb0ba52b197bb066f';CK='98ad7b81687304aa0e99cf326200adfe';T='faedca88d0a0ab30dae5519239582d31';TC='3d42bf2e42127f313b0ec64cb440cde9'
def header(ar,off,key):
 h=bytes.fromhex(key)[::-1]+struct.pack('<I',188)+bytes(2);h+=struct.pack('<I',fmt.hashlittle2(h,0x3d6be971)[0]);return h+fmt.checksum_b(h,ar,off)
class Policy(unittest.TestCase):
 def test_range_first(self):self.assertTrue(io.range_model(480,188)['valid'])
 def test_range_last_supported(self):self.assertTrue(io.range_model((1022<<30)+480,188)['valid'])
 def test_1023_rejected(self):self.assertFalse(io.range_model((1023<<30)+480,188)['valid'])
 def test_cross_rejected(self):self.assertFalse(io.range_model((1<<30)-2,3)['valid'])
 def test_exact_end(self):self.assertTrue(io.range_model((1<<30)-2,2)['valid'])
 def test_zero_length(self):self.assertTrue(io.range_model(0,0)['valid'])
 def test_high_alias_is_primitive_only(self):self.assertTrue(io.range_model((1<<62)+480,188)['valid'])
 def test_bool(self):
  with self.assertRaises(a.AuditError):io.inputs(True,1)
 def test_negative(self):
  with self.assertRaises(a.AuditError):io.inputs(-1,1)
 def test_u64_overflow(self):
  with self.assertRaises(a.AuditError):io.inputs(1<<64,1)
 def test_length_limit(self):
  with self.assertRaises(a.AuditError):io.inputs(0,4097)
 def test_mode_limit(self):
  with self.assertRaises(a.AuditError):io.inputs(0,1,2)
 def test_error_limit(self):
  with self.assertRaises(a.AuditError):io.inputs(0,1,0,1<<32)
@unittest.skipUnless(O.is_file(),'original archive IO oracle required')
class Native(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.p=Path(self.t.name)/'data.000';self.raw=bytes(range(256))*4;self.p.write_bytes(self.raw)
 def tearDown(self):self.t.cleanup()
 def runio(self,addr=480,length=188,**kw):return io.compare(O,self.p,addr,length,**kw)
 def test_exact(self):self.assertEqual(self.runio()[1],self.raw[480:668])
 def test_offset_applied(self):self.assertEqual(self.runio(668)[1],self.raw[668:856])
 def test_mode0_flags(self):self.assertEqual(self.runio()[0]['open_flags'],1)
 def test_mode1_flags(self):self.assertEqual(self.runio(mode=1)[0]['open_flags'],4)
 def test_zero_does_not_open(self):self.assertEqual(self.runio(length=0)[0]['open_calls'],0)
 def test_short_success_is_not_complete(self):self.assertEqual(self.runio(1020,20)[0]['actual_bytes'],4)
 def test_eof_success_is_not_complete(self):self.assertEqual(self.runio(1024,20)[0]['actual_bytes'],0)
 def test_boundary_reject_before_open(self):self.assertEqual(self.runio((1<<30)-2,3)[0]['open_calls'],0)
 def test_1023_reject_before_open(self):self.assertEqual(self.runio((1023<<30)+480)[0]['status'],10)
 def test_1022_selected(self):self.assertEqual(self.runio((1022<<30)+480)[0]['archive'],1022)
 def test_high_alias_original_only(self):self.assertEqual(self.runio((1<<62)+480)[0]['archive'],0)
 def test_open_error_preserved(self):self.assertEqual(self.runio(open_error=7)[0]['status'],7)
 def test_read_error_mapped(self):self.assertEqual(self.runio(read_error=5)[0]['status'],8)
 def test_eof_error38_success(self):self.assertEqual(self.runio(read_error=38)[0]['status'],0)
 def test_release_success(self):self.assertEqual(self.runio()[0]['releases'],1)
 def test_release_on_read_error(self):self.assertEqual(self.runio(read_error=5)[0]['releases'],1)
 def test_no_release_failed_open(self):self.assertEqual(self.runio(open_error=5)[0]['releases'],0)
 def test_seeded_matrix(self):
  r=random.Random(9824)
  for _ in range(120):self.runio((r.choice([0,3,4,1022,1023])<<30)+r.randrange(1000,1100),r.randrange(100),mode=r.randrange(2),read_error=r.choice([0,0,5,38]),open_error=r.choice([0,0,7]))
 def test_unchanged(self):self.runio();self.assertEqual(self.p.read_bytes(),self.raw)
 def test_symlink(self):
  p=self.p.parent/'link';p.symlink_to(self.p)
  with self.assertRaises(b.BindingError):io.native(O,p,480,188)
 def test_hardlink(self):
  p=self.p.parent/'link';os.link(self.p,p)
  with self.assertRaises(b.BindingError):io.native(O,self.p,480,188)
 def test_bad_digest(self):
  p=self.p.parent/'oracle';p.write_bytes(O.read_bytes()+b'x');p.chmod(0o700);(p.parent/'BUILD-RECEIPT.json').write_bytes((O.parent/'BUILD-RECEIPT.json').read_bytes())
  with self.assertRaises(a.AuditError):io.native(p,self.p,480,188)
@unittest.skipUnless(O.is_file() and S.is_file() and (P/'data.000').is_file(),'IO/span oracles and research fixture required')
class Bridge(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.files={};self.raw=(P/'data.000').read_bytes()
  for ar in (0,3,4,1022):
   raw=bytearray(856)
   for off,key in ((480,K),(668,T)):raw[off:off+188]=header(ar,off,key)+self.raw[off+30:off+188]
   p=self.root/f'data.{ar:03d}';p.write_bytes(raw);self.files[ar]=p
 def tearDown(self):self.t.cleanup()
 def read(self,ar=0,off=480,key=K,ck=CK,size=188):return io.read_numbered(O,S,self.files,(ar<<30)+off,size,key,33940,ck)
 def test_source_target_four_archives(self):
  for ar in self.files:
   for off,key,ck in ((480,K,CK),(668,T,TC)):self.assertEqual(self.read(ar,off,key,ck)['decoded_bytes'],33940)
 def test_1023_not_admitted(self):
  with self.assertRaisesRegex(a.AuditError,'io_reader_address_profile'):self.read(1023)
 def test_high_alias_not_admitted(self):
  with self.assertRaisesRegex(a.AuditError,'io_reader_address_profile'):io.read_numbered(O,S,self.files,(1<<62)+480,188,K,33940,CK)
 def test_short_rejected(self):
  self.files[0].write_bytes(self.raw[:600])
  with self.assertRaisesRegex(a.AuditError,'io_reader_exact_read_required'):self.read()
 def test_eof_rejected(self):
  self.files[0].write_bytes(bytes(480))
  with self.assertRaisesRegex(a.AuditError,'io_reader_exact_read_required'):self.read()
 def test_corrupt_header(self):
  raw=bytearray(self.files[0].read_bytes());raw[506]^=1;self.files[0].write_bytes(raw)
  with self.assertRaisesRegex(a.AuditError,'io_reader_original_header_rejected'):self.read()
 def test_wrong_key(self):
  with self.assertRaisesRegex(a.AuditError,'io_reader_key_size_flag'):self.read(key=T,ck=TC)
 def test_wrong_ck(self):
  with self.assertRaises(fmt.FormatError):self.read(ck=TC)
 def test_missing_explicit_archive(self):
  del self.files[0]
  with self.assertRaisesRegex(a.AuditError,'io_reader_explicit_archive_required'):self.read()
 def test_misnamed(self):
  q=self.root/'other';q.write_bytes(self.files[0].read_bytes());self.files[0]=q
  with self.assertRaisesRegex(a.AuditError,'io_reader_numbered_filename'):self.read()
 def test_size_limit(self):
  with self.assertRaisesRegex(a.AuditError,'io_reader_size_profile'):self.read(size=4097)
 def test_no_windows_claim(self):self.assertFalse(self.read()['windows_executed'])
