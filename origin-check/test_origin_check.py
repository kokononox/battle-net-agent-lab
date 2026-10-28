import hashlib,os,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import origin_check as c,lookup3

def prefix(host='synthetic-host',archive=0):
 seed=hashlib.md5(host.encode()+b'data/data').digest()[2:9];out=b''
 for i in range(16):
  key=bytes([i,archive])+seed+bytes(7);h=key[::-1]+(30).to_bytes(4,'little')+b'\x01\x00';out+=h+lookup3.hashlittle(h,0x3D6BE971).to_bytes(4,'little')+bytes(4)
 return out
class Offline(unittest.TestCase):
 def test_prediction_and_copy(self):
  with tempfile.TemporaryDirectory()as t,patch.object(c.socket,'gethostname',return_value='synthetic-host'):
   root=Path(t);first=root/'first/Data/data';first.mkdir(parents=True);second=root/'second/Data/data';second.mkdir(parents=True);raw=prefix();(first/'data.000').write_bytes(raw);(second/'data.000').write_bytes(raw)
   a,pa=c.inspect(root/'first');b,pb=c.inspect(root/'second');self.assertEqual(pa,pb);self.assertTrue(a['matches_current_hostname_prediction']);self.assertNotIn('synthetic-host',str(a));self.assertFalse(a['game_payload_watermark_proven'])
 def test_changed_host(self):
  with tempfile.TemporaryDirectory()as t,patch.object(c.socket,'gethostname',return_value='other-host'):
   (Path(t)/'data.000').write_bytes(prefix());r,_=c.inspect(t);self.assertTrue(r['marker_layout_observed']);self.assertFalse(r['matches_current_hostname_prediction'])
 def test_corrupt_checksum(self):
  raw=bytearray(prefix());raw[22]^=1;self.assertEqual(c.extract(bytes(raw),0),set())
 def test_wrong_archive(self):self.assertEqual(c.extract(prefix(),1),set())
 def test_partial(self):self.assertEqual(c.extract(prefix()[:-1],0),set())
 def test_nonzero_prefix_offset(self):self.assertTrue(c.extract(bytes(1024)+prefix(),0))
 def test_duplicated_records(self):self.assertEqual(c.extract(prefix()[:30]*16,0),set())
 def test_empty_not_absence(self):
  with tempfile.TemporaryDirectory()as t:
   r,_=c.inspect(t);self.assertFalse(r['marker_layout_observed']);self.assertIsNone(r['matches_current_hostname_prediction']);self.assertFalse(r['whole_game_scanned'])
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);(d/'real').write_bytes(prefix());(d/'data.000').symlink_to(d/'real')
   with self.assertRaises(c.Refused):c.inspect(d)
 def test_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);(d/'real').write_bytes(prefix());os.link(d/'real',d/'data.000')
   with self.assertRaises(c.Refused):c.inspect(d)
if __name__=='__main__':unittest.main()
