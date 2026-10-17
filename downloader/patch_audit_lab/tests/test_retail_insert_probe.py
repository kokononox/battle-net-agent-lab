"""Requires the separately verified real portable fixture created by the probe."""
import hashlib,json,os,shutil,tempfile,unittest
from pathlib import Path
import agent_archive_insert as insert
import patch_audit as a
import retail_insert_probe as p
import source_binding as b
INSERT=Path(os.environ['ARCHIVE_INSERT_ORACLE']).resolve()
SPAN=Path(os.environ['SPAN_ORACLE']).resolve()
FIXTURE=Path(os.environ['RETAIL_INSERT_FIXTURE']).resolve()
class RealRetailInsertTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'fixture';shutil.copytree(FIXTURE,self.root)
 def tearDown(self):self.temp.cleanup()
 def read(self,ads=None,**kw):return p.probe(INSERT,SPAN,self.root,ads or [480,668,480,668],**kw)
 def reject(self,ads=None,**kw):
  with self.assertRaises((a.AuditError,b.BindingError)):self.read(ads,**kw)
 def change(self,offset):
  f=self.root/'data.000';raw=bytearray(f.read_bytes());raw[offset]^=1;f.write_bytes(raw)
 def test_source_target_exact_keys(self):self.assertEqual([r['ekey'] for r in self.read()],[p.SOURCE,p.TARGET]*2)
 def test_one_open_and_constructor(self):
  rows=self.read();self.assertEqual([r['trace']['create_calls'] for r in rows],[1]*4);self.assertEqual([r['trace']['constructor_calls'] for r in rows],[1]*4)
 def test_reference_two_during_one_after(self):
  for r in self.read():self.assertEqual((r['trace']['new_reference_during_read'],r['trace']['new_reference_after']),(2,1))
 def test_two_archive_reuse(self):
  rows=self.read([480,(1<<30)+480,668,(1<<30)+668]);self.assertEqual([r['trace']['create_calls'] for r in rows],[1,2,2,2]);self.assertEqual([r['trace']['constructor_calls'] for r in rows],[1,2,2,2])
 def test_lru_alternation(self):self.assertEqual([r['trace']['list_head'] for r in self.read([480,(1<<30)+480,668,(1<<30)+668])],[0,1,0,1])
 def test_archives_unchanged_by_probe(self):
  before={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in self.root.iterdir()};self.read();self.assertEqual(before,{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in self.root.iterdir()})
 def test_corrupt_header_rejected(self):self.change(480+22);self.reject([480])
 def test_corrupt_source_payload_rejected(self):self.change(480+45);self.reject([480])
 def test_corrupt_target_payload_rejected(self):self.change(668+45);self.reject([668])
 def test_source_target_swap_rejected(self):
  f=self.root/'data.000';raw=f.read_bytes();f.write_bytes(raw[:480]+raw[668:856]+raw[480:668]);self.reject()
 def test_truncated_target_rejected(self):
  f=self.root/'data.000';f.write_bytes(f.read_bytes()[:-1]);self.reject([668])
 def test_status_zero_eof_is_rejected(self):self.reject(read_error=38,read_error_on=2)
 def test_read_error_rejected(self):self.reject(read_error=5,read_error_on=2)
 def test_open_error_rejected(self):self.reject(open_error=5,open_error_on=1)
 def test_open_error_on_hit_not_called(self):self.assertEqual(len(self.read(open_error=5,open_error_on=2)),4)
 def test_unmarked_fixture_rejected(self):
  (self.root/insert.MARKER).unlink()
  with self.assertRaises(FileNotFoundError):self.read()
 def test_wrong_address_profile_rejected(self):self.reject([481])
 def test_write_mode_rejected(self):self.reject(mode=0)
if __name__=='__main__':unittest.main(verbosity=2)
