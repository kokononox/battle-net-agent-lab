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
class Batches(unittest.TestCase):
 def files(self,folder,count):
  for i in range(count):(folder/('data.%03d'%i)).write_bytes(bytes(480))
 def test_more_than64_no_longer_refused(self):
  with tempfile.TemporaryDirectory()as t:
   self.files(Path(t),70);r,_=c.inspect(t);self.assertEqual(r['archives_checked'],64);self.assertEqual(r['total_eligible_archives'],70);self.assertEqual(r['next_batch_start'],64);self.assertFalse(r['archive_scan_complete']);self.assertEqual(r['archives_not_checked_this_run'],6);self.assertLessEqual(r['prefix_bytes_read'],64*65536)
 def test_next_batch_reads_remaining_only(self):
  with tempfile.TemporaryDirectory()as t:
   self.files(Path(t),70);r,_=c.inspect(t,64);self.assertEqual(r['archives_checked'],6);self.assertIsNone(r['next_batch_start']);self.assertFalse(r['archive_scan_complete']);self.assertFalse(r['whole_game_scanned'])
 def test_invalid_cursor_refused(self):
  with tempfile.TemporaryDirectory()as t:
   for x in (-64,1,True,4097):
    with self.assertRaises(c.Refused):c.inspect(t,x)
 def test_unsupported_archive_ids_not_silently_complete(self):
  with tempfile.TemporaryDirectory()as t:
   (Path(t)/'data.256').write_bytes(bytes(480));r,_=c.inspect(t);self.assertEqual(r['unsupported_archive_ids'],1);self.assertFalse(r['archive_scan_complete']);self.assertEqual(r['archives_checked'],0)
 def test_second_directory_shorter_batch_is_valid(self):
  with tempfile.TemporaryDirectory()as t:
   self.files(Path(t),2);r,_=c.inspect(t,64);self.assertEqual(r['archives_checked'],0);self.assertFalse(r['more_archives_available']);self.assertFalse(r['archive_scan_complete'])
 def test_partial_batch_equality_not_full_set_claim(self):
  import io,json
  from contextlib import redirect_stdout
  with tempfile.TemporaryDirectory()as t:
   a=Path(t)/'a';b=Path(t)/'b';a.mkdir();b.mkdir();self.files(a,65);self.files(b,65);(a/'data.000').write_bytes(prefix());(b/'data.000').write_bytes(prefix());out=io.StringIO()
   with redirect_stdout(out):code=c.main([str(a),str(b)])
   r=json.loads(out.getvalue());self.assertEqual(code,0);self.assertTrue(r['observed_batch_marker_sets_equal']);self.assertIsNone(r['two_copy_marker_sets_equal']);self.assertEqual(r['tool_version'],'5.0')
if __name__=='__main__':unittest.main()
