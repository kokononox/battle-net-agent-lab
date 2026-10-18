import struct,unittest
from release_core import InvalidRelease
from lookup3 import hashlittle2
from local_v8_readonly import primary_records,align

def fixture(rows=None,maxoff=0xffffffffffffffff):
 rows=rows if rows is not None else [b'e'*16+struct.pack('<QQ',123,456)];h=struct.pack('<HBBBBBBQ',8,0,0,8,8,16,30,maxoff);hi=lo=0
 for r in rows:hi,lo=hashlittle2(r,hi,lo)
 raw=struct.pack('<II',16,hashlittle2(h)[0])+h+bytes(8)+struct.pack('<II',len(rows)*32,hi)+b''.join(rows);return raw+bytes(align(align(len(raw),4096)+0x7800,0x20000)-len(raw))
class V8Tests(unittest.TestCase):
 def test_actual_header_family_not_fixture_maxoff(self):
  rows,p=primary_records(fixture(),0);self.assertEqual(rows[0]['opaque_qword0'],123);self.assertFalse(p['native_fixture_header_max_offset_match']);self.assertFalse(p['native_agent_executed'])
 def test_fixture_maxoff(self):self.assertTrue(primary_records(fixture(maxoff=0x4000000000),0)[1]['native_fixture_header_max_offset_match'])
 def test_empty_primary(self):self.assertEqual(primary_records(fixture([]),0)[0],[])
 def test_header_damage(self):
  r=bytearray(fixture());r[4]^=1
  with self.assertRaises(InvalidRelease):primary_records(bytes(r),0)
 def test_primary_damage(self):
  r=bytearray(fixture());r[41]^=1
  with self.assertRaises(InvalidRelease):primary_records(bytes(r),0)
 def test_tail_not_silently_skipped(self):
  r=bytearray(fixture());r[-1]=1
  with self.assertRaises(InvalidRelease):primary_records(bytes(r),0)
 def test_wrong_bucket(self):
  with self.assertRaises(InvalidRelease):primary_records(fixture(),1)
 def test_duplicate_keys(self):
  row=b'e'*16+struct.pack('<QQ',1,2)
  with self.assertRaises(InvalidRelease):primary_records(fixture([row,row]),0)
 def test_unsorted(self):
  rows=[b'z'*16+bytes(16),b'a'*16+bytes(16)]
  with self.assertRaises(InvalidRelease):primary_records(fixture(rows),0)
 def test_unknown_size_profile(self):
  with self.assertRaises(InvalidRelease):primary_records(fixture()[:-1],0)
if __name__=='__main__':unittest.main()
