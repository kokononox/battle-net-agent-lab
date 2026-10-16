import json,os,random,struct,tempfile,unittest
from pathlib import Path
import agent_span_reader as s
import synthetic_casc_format as f
import agent_lookup_merge as lookup
import agent_bind_contract as bind
import patch_audit as a
K='914fcad4f4fcf4abb0ba52b197bb066f';CK='98ad7b81687304aa0e99cf326200adfe'
T='faedca88d0a0ab30dae5519239582d31';TC='3d42bf2e42127f313b0ec64cb440cde9'
ORACLE=Path(os.environ.get('SPAN_READER_ORACLE','/missing'));LOOKUP=Path(os.environ.get('LOOKUP_MERGE_ORACLE','/missing'));FIXTURE=Path(os.environ.get('SPAN_PRIOR_STORE','/missing'))
def header(archive=0,offset=480,size=188,flag=0,reserved=0,key=K):
 h=bytes.fromhex(key)[::-1]+struct.pack('<I',size)+bytes((flag,reserved));h+=struct.pack('<I',f.hashlittle2(h,0x3d6be971)[0]);return h+f.checksum_b(h,archive,offset)
class Policy(unittest.TestCase):
 def test_valid(self):self.assertTrue(s.model(header(),480)['valid'])
 def test_short_available(self):self.assertFalse(s.model(header(),480,29)['valid'])
 def test_available_not_full_span_requirement(self):self.assertTrue(s.model(header(),480,30)['valid'])
 def test_flag1_accepted_by_original(self):self.assertTrue(s.model(header(flag=1),480)['valid'])
 def test_flag2_rejected(self):self.assertFalse(s.model(header(flag=2),480)['valid'])
 def test_reserved_not_checked_by_original(self):self.assertTrue(s.model(header(reserved=255),480)['valid'])
 def test_size_zero_not_checked_by_original(self):self.assertTrue(s.model(header(size=0),480)['valid'])
 def test_size_large_not_checked_by_original(self):self.assertTrue(s.model(header(size=0xffffffff),480)['valid'])
 def test_wrong_offset_rejected(self):self.assertFalse(s.model(header(),481)['valid'])
 def test_width_rejected(self):
  with self.assertRaises(a.AuditError):s.model(bytes(29),0)
 def test_negative_rejected(self):
  with self.assertRaises(a.AuditError):s.model(header(),-1)
 def test_uint64_overflow_rejected(self):
  with self.assertRaises(a.AuditError):s.model(header(),1<<64)
 def test_available_bool_rejected(self):
  with self.assertRaises(a.AuditError):s.model(header(),480,True)
@unittest.skipUnless(ORACLE.is_file(),'original span reader oracle required')
class Native(unittest.TestCase):
 def cmp(self,h=None,address=480,available=30):return s.compare(ORACLE,header() if h is None else h,address,available)
 def test_success(self):self.assertEqual(self.cmp()['payload_offset'],510)
 def test_no_helpers(self):self.assertEqual(json.loads((ORACLE.parent/'BUILD-RECEIPT.json').read_text())['helpers'],{})
 def test_all_alignment_and_archives(self):
  for ar in (0,1,3,4,256,1023):
   for off in range(480,496):self.assertEqual(self.cmp(header(ar,off),(ar<<30)+off)['archive'],ar)
 def test_all_single_bit_header_corruptions(self):
  h=header()
  for bit in range(240):
   bad=bytearray(h);bad[bit//8]^=1<<(bit%8);self.assertFalse(self.cmp(bytes(bad))['valid'])
 def test_all_flag_values(self):
  for flag in range(256):self.assertEqual(self.cmp(header(flag=flag))['valid'],flag in (0,1))
 def test_reserved_byte_accepted(self):self.assertTrue(self.cmp(header(reserved=255))['valid'])
 def test_size_not_validated(self):
  for size in (0,1,29,30,188,0xffffffff):self.assertTrue(self.cmp(header(size=size))['valid'])
 def test_short_available(self):
  for n in (0,1,29):self.assertFalse(self.cmp(available=n)['valid'])
 def test_large_available(self):self.assertTrue(self.cmp(available=0xffffffff)['valid'])
 def test_relocate4g_same_checksum_not_identity(self):self.assertTrue(self.cmp(address=(4<<30)+480)['valid'])
 def test_wrong_offset(self):self.assertFalse(self.cmp(address=481)['valid'])
 def test_digest_mutation_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'span_reader_oracle';p.write_bytes(ORACLE.read_bytes()+b'x');p.chmod(0o700);(p.parent/'BUILD-RECEIPT.json').write_bytes((ORACLE.parent/'BUILD-RECEIPT.json').read_bytes())
   with self.assertRaises(a.AuditError):s.native(p,header(),480)
@unittest.skipUnless(ORACLE.is_file() and LOOKUP.is_file() and (FIXTURE/'data.000').is_file(),'span/lookup oracles and completed research store required')
class NumberedBridge(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.original=(FIXTURE/'data.000').read_bytes();self.files={}
  for ar in (0,3,4,1023):
   raw=bytearray(856)
   for off,key in ((480,K),(668,T)):raw[off:off+188]=header(ar,off,key=key)+self.original[off+30:off+188]
   p=self.root/f'data.{ar:03d}';p.write_bytes(raw);self.files[ar]=p
 def tearDown(self):self.temp.cleanup()
 def read(self,ar=0,off=480,key=K,ckey=CK,span=188,files=None):return s.read_numbered(ORACLE,self.files if files is None else files,(ar<<30)+off,span,key,33940,ckey)
 def test_real_source_target_all_archives(self):
  for ar in self.files:
   for off,key,ck in ((480,K,CK),(668,T,TC)):
    raw=lookup.build_index([bind.record(key,(ar<<30)+off,188)],[],f.bucket(key));found=lookup.compare(LOOKUP,raw,f.bucket(key),key)['lookup'];self.assertEqual(found['status'],0);address,span=found['range'];proof=s.read_numbered(ORACLE,self.files,address,span,key,33940,ck);self.assertEqual(proof['decoded_bytes'],33940);self.assertEqual(proof['archive'],ar)
 def test_no_write_original_or_copies(self):
  before={ar:p.read_bytes() for ar,p in self.files.items()};self.read();self.assertEqual(before,{ar:p.read_bytes() for ar,p in self.files.items()});self.assertEqual(self.original,(FIXTURE/'data.000').read_bytes())
 def test_missing_archive_no_fallback(self):
  with self.assertRaises(a.AuditError):self.read(ar=1)
 def test_wrong_file_name(self):
  with self.assertRaises(a.AuditError):self.read(ar=3,files={3:self.files[0]})
 def test_full_key_mismatch(self):
  with self.assertRaises(a.AuditError):self.read(key='00'*16)
 def test_index_span_mismatch(self):
  with self.assertRaises(a.AuditError):self.read(span=187)
 def test_payload_mutation(self):
  p=self.files[0];raw=bytearray(p.read_bytes());raw[540]^=1;p.write_bytes(raw)
  with self.assertRaises((a.AuditError,f.FormatError,ValueError)):self.read()
 def test_truncated_file(self):
  self.files[0].write_bytes(self.original[:600])
  with self.assertRaises(a.AuditError):self.read()
 def test_symlink_rejected(self):
  p=self.root/'links';p.mkdir();link=p/'data.000';link.symlink_to(self.files[0])
  with self.assertRaises(ValueError):self.read(files={0:link})
 def test_hardlink_rejected(self):
  p=self.root/'other';os.link(self.files[0],p)
  with self.assertRaises(ValueError):self.read()
 def test_segment_cross_rejected_before_io(self):
  with self.assertRaises(a.AuditError):self.read(off=(1<<30)-100)
 def test_prefix_offset_rejected(self):
  with self.assertRaises(a.AuditError):self.read(off=0)

 def test_ckey_mismatch(self):
  with self.assertRaises((a.AuditError,f.FormatError,ValueError)):self.read(ckey='00'*16)
 def test_flag1_parser_accepts_reader_rejects(self):
  p=self.files[0];raw=bytearray(p.read_bytes());raw[480:510]=header(flag=1);p.write_bytes(raw)
  self.assertTrue(s.compare(ORACLE,bytes(raw[480:510]),480)['valid'])
  with self.assertRaises(a.AuditError):self.read()
 def test_reserved_parser_accepts_reader_rejects(self):
  p=self.files[0];raw=bytearray(p.read_bytes());raw[480:510]=header(reserved=9);p.write_bytes(raw)
  self.assertTrue(s.compare(ORACLE,bytes(raw[480:510]),480)['valid'])
  with self.assertRaises(f.FormatError):self.read()
 def test_original_rejects_bad_header_before_payload(self):
  p=self.files[0];raw=bytearray(p.read_bytes());raw[506]^=1;p.write_bytes(raw)
  with self.assertRaisesRegex(a.AuditError,'span_reader_original_header_rejected'):self.read()
 def test_archive_profile_limit(self):
  with self.assertRaises(a.AuditError):self.read(ar=1024)
