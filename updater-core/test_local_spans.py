import unittest,struct
from local_spans import span_checksum_b,verify_span
from lookup3 import hashlittle2
from release_core import InvalidRelease
from test_local_candidates import fixture

def sample():
 d,raw,spec,ref,index=fixture();s=dict(spec.public(),archive_id=3,offset=700,index_span=len(raw)+30);h=bytes.fromhex(s['ekey'])[::-1]+struct.pack('<I',len(raw)+30)+bytes(2);h+=hashlittle2(h,0x3D6BE971)[0].to_bytes(4,'little');h+=span_checksum_b(h,3,700);return h+raw,s
class Tests(unittest.TestCase):
 def test_span_and_object(self):
  raw,s=sample();p=verify_span(raw,s);self.assertTrue(p['archive_header_checksum_b_verified']);self.assertTrue(p['full_ckey_verified'])
 def test_checksum_a(self):
  raw,s=sample();raw=raw[:22]+bytes([raw[22]^1])+raw[23:]
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_checksum_b(self):
  raw,s=sample();raw=raw[:26]+bytes([raw[26]^1])+raw[27:]
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_key(self):
  raw,s=sample();s['ekey']='0'*32
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_size(self):
  raw,s=sample()
  with self.assertRaises(InvalidRelease):verify_span(raw[:-1],s)
 def test_location(self):
  raw,s=sample();s['offset']+=1
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_archive(self):
  raw,s=sample();s['archive_id']+=1
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_flags(self):
  raw,s=sample();raw=raw[:20]+b'\1\0'+raw[22:]
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
 def test_segment_boundary(self):
  raw,s=sample();s['offset']=(1<<30)-1
  with self.assertRaises(InvalidRelease):verify_span(raw,s)
if __name__=='__main__':unittest.main()
