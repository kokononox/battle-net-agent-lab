import os,struct,random,unittest
from pathlib import Path
import agent_bind_contract as v
import synthetic_casc_format as fmt
import patch_audit as a
KEY='914fcad4f4fcf4abb0ba52b197bb066f'
ORACLE=Path(os.environ.get('BIND_CONTRACT_ORACLE','/missing'))
def altered(raw,at,value):
 r=bytearray(raw);r[at:at+len(value)]=value;return bytes(r)
def header(raw,at,value):
 r=bytearray(altered(raw,at,value));struct.pack_into('<I',r,4,fmt.hashlittle2(bytes(r[8:24]))[0]);return bytes(r)
def primary(rows,bucket=5,remainder=b''):
 r=bytearray(v.make_index([],bucket));size=32*len(rows)+len(remainder);r[40:40+size]=b''.join(rows)+remainder;hi=lo=0
 for row in rows:hi,lo=fmt.hashlittle2(row,hi,lo)
 struct.pack_into('<II',r,32,size,hi);return bytes(r)
class BindPolicy(unittest.TestCase):
 def setUp(self):self.raw=v.make_index([v.record(KEY,480,188)],5)
 def test_profile(self):self.assertEqual(v.strict_read(self.raw,5),[v.record(KEY,480,188)])
 def test_size(self):self.assertEqual(len(self.raw),131072)
 def test_empty_profile(self):self.assertEqual(v.strict_read(v.make_index([],0),0),[])
 def test_duplicate_builder_rejected(self):
  with self.assertRaises(a.AuditError):v.make_index([v.record(KEY,1,1)]*2,5)
 def test_bad_record_width(self):
  with self.assertRaises(a.AuditError):v.make_index([b'x'],0)
 def test_wrong_bucket_rejected(self):
  with self.assertRaises(a.AuditError):v.strict_read(self.raw,4)
 def test_flags_rejected_by_policy(self):
  with self.assertRaises(a.AuditError):v.strict_read(header(self.raw,11,b'\1'),5)
 def test_future_revision_rejected_by_policy(self):
  with self.assertRaises(a.AuditError):v.strict_read(header(self.raw,8,b'\x09\x00'),5)
 def test_segmentbits_rejected_by_policy(self):
  with self.assertRaises(a.AuditError):v.strict_read(header(self.raw,15,b'\x1f'),5)
 def test_remainder_rejected(self):
  with self.assertRaises(a.AuditError):v.strict_read(primary([v.record(KEY,1,2)],remainder=b'x'),5)
 def test_unsorted_rejected(self):
  with self.assertRaises(a.AuditError):v.strict_read(primary([v.record('ff'*16,1,2),v.record('00'*16,3,4)]),5)
 def test_duplicate_reader_rejected(self):
  with self.assertRaises(a.AuditError):v.strict_read(primary([v.record(KEY,1,2)]*2),5)
 def test_ignored_tail_garbage_rejected(self):
  with self.assertRaises(a.AuditError):v.strict_read(altered(self.raw,5000,b'x'),5)
 def test_unsafe_header_length_not_sent_native(self):
  with self.assertRaises(a.AuditError):v.admissible(altered(self.raw,0,b'\xff'*4),5)
 def test_unsafe_primary_length_not_sent_native(self):
  with self.assertRaises(a.AuditError):v.admissible(altered(self.raw,32,b'\xff'*4),5)
 def test_qword_bounds(self):
  for x in (-1,1<<64,True):
   with self.assertRaises(a.AuditError):v.record(KEY,x,188)
 def test_full_key_collision_is_not_duplicate(self):
  other=KEY[:18]+'00'*7;self.assertEqual(len(v.strict_read(v.make_index([v.record(KEY,1,2),v.record(other,3,4)],5),5)),2)

@unittest.skipUnless(ORACLE.is_file(),'bounded original bind/parser/search oracle required')
class BindNative(unittest.TestCase):
 def setUp(self):self.raw=v.make_index([v.record(KEY,480,188)],5)
 def cmp(self,raw=None,bucket=5,**kw):return v.compare(ORACLE,self.raw if raw is None else raw,bucket,**kw)
 def test_all_buckets(self):
  for i in range(16):self.assertEqual(self.cmp(v.make_index([v.record(KEY,i,188)],i),i)['status'],0)
 def test_v7_rejected(self):self.assertEqual(self.cmp(header(self.raw,8,b'\7\0'))['status'],5)
 def test_real_v7_widths_rejected(self):
  h=struct.pack('<HBBBBBBQ',7,5,0,4,5,9,30,0x4000000000);self.assertEqual(self.cmp(altered(altered(self.raw,8,h),4,struct.pack('<I',fmt.hashlittle2(h)[0])))['status'],5)
 def test_checksum_header_rejected(self):self.assertEqual(self.cmp(altered(self.raw,4,b'\0'*4))['status'],9)
 def test_checksum_primary_rejected(self):self.assertEqual(self.cmp(altered(self.raw,40,b'x'))['status'],9)
 def test_widths_rejected(self):
  for at in (12,13,14):self.assertEqual(self.cmp(header(self.raw,at,b'\x03'))['status'],5)
 def test_bucket_rejected(self):self.assertEqual(self.cmp(bucket=6)['status'],9)
 def test_short_header(self):self.assertEqual(self.cmp(b'\0'*7)['status'],9)
 def test_small_guarded_header(self):self.assertEqual(self.cmp(struct.pack('<II',0,fmt.hashlittle2(b'')[0])+bytes(32))['status'],5)
 def test_truncated_primary(self):self.assertEqual(self.cmp(self.raw[:41])['status'],9)
 def test_truncated_tail(self):self.assertEqual(self.cmp(self.raw[:4096+0x77ff])['status'],9)
 def test_mapping_failure_cleanup(self):
  for code in (1,73,0xffffffff):self.assertEqual(self.cmp(map_error=code)['status'],code)
 def test_flags_only_warning(self):self.assertEqual(self.cmp(header(self.raw,11,b'\1'))['log_calls'],1)
 def test_future_revision_accepted_not_policy(self):self.assertEqual(self.cmp(header(self.raw,8,b'\x09\0'))['status'],0)
 def test_segment_bits_unchecked_here(self):self.assertEqual(self.cmp(header(self.raw,15,b'\x1f'))['status'],0)
 def test_empty_primary(self):self.assertEqual(self.cmp(v.make_index([],5),query=KEY)['records'],0)
 def test_full_key_found(self):self.assertEqual(self.cmp(query=KEY)['selected'],v.record(KEY,480,188).hex())
 def test_full_key_not_found(self):self.assertIsNone(self.cmp(query='00'*16)['selected'])
 def test_same9_prefix_full16_search(self):
  other=KEY[:18]+'00'*7;r=v.make_index([v.record(KEY,480,188),v.record(other,668,188)],5)
  for key,offset in ((KEY,480),(other,668)):self.assertEqual(self.cmp(r,query=key)['selected'],v.record(key,offset,188).hex())
 def test_duplicate_range(self):self.assertEqual(self.cmp(primary([v.record(KEY,1,2)]*3),query=KEY)['end'],3)
 def test_primary_remainder_ignored(self):self.assertEqual(self.cmp(primary([v.record(KEY,1,2)],remainder=b'x'))['status'],0)
 def test_unsorted_parse_is_not_sortedness_proof(self):self.assertEqual(self.cmp(primary([v.record('ff'*16,1,2),v.record('00'*16,3,4)]))['status'],0)
 def test_tail_after_terminator_ignored(self):self.assertEqual(self.cmp(altered(self.raw,5000,b'x'))['status'],0)
 def test_nonzero_valid_tail_slot_uses_original_hashlittle(self):
  payload=v.record(KEY,480,188)+b'\1';slot=struct.pack('<I',fmt.hashlittle2(payload)[0]|0x80000000)+payload+bytes(3);self.assertEqual(self.cmp(altered(self.raw,4096,slot))['status'],0)
 def test_corrupt_nonzero_tail_slot(self):self.assertEqual(self.cmp(altered(self.raw,4096,b'\1'))['status'],9)
 def test_deterministic_fullkey_search_vectors(self):
  rng=random.Random(982408)
  for i in range(100):
   keys=sorted({rng.randbytes(16).hex() for j in range(rng.randrange(1,25))});rows=[v.record(k,rng.getrandbits(64),rng.getrandbits(64)) for k in keys];bucket=i%16;raw=v.make_index(rows,bucket)
   for query in (rng.choice(keys),rng.randbytes(16).hex()):self.cmp(raw,bucket,query=query)
