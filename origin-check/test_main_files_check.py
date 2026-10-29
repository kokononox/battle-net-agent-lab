import hashlib,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import main_files_check as m
class MainFiles(unittest.TestCase):
 def fixture(self,t):
  root=Path(t);(root/'_retail_').mkdir();(root/'.build.info').write_text('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Product!STRING:0\n1|'+m.ref.BUILD_KEY+'|'+m.ref.VERSION+'|wow\n')
  data={k:('synthetic-'+k).encode()for k in m.ref.MAIN_FILES}
  for label,b in data.items():(root/'_retail_'/m.ref.MAIN_FILES[label]).write_bytes(b)
  return root,{k:[dict(size=len(b),ckey=hashlib.md5(b).hexdigest())]for k,b in data.items()}
 def test_full_checks_without_execution(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t)
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertTrue(r['all_selected_components_match']);self.assertEqual(r['verified_components'],2);self.assertTrue(r['client_executable_checked']);self.assertTrue(r['client_loader_checked']);self.assertFalse(r['game_executed']);self.assertFalse(r['archive_files_read']);self.assertFalse(r['network_requested'])
 def test_wrong_build_stops(self):
  with tempfile.TemporaryDirectory()as t:
   root,_=self.fixture(t);p=root/'.build.info';p.write_text(p.read_text().replace(m.ref.VERSION,'12.1.5.70575'));r=m.assess(root);self.assertEqual(r['error_kind'],'build_mismatch');self.assertFalse(r['client_executable_checked'])
 def test_size_mismatch_not_hashed(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);(root/'_retail_'/m.ref.MAIN_FILES['client_executable']).write_bytes(b'x')
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertEqual(r['components']['client_executable']['status'],'size_not_in_reference');self.assertFalse(r['client_executable_checked'])
 def test_mutated_content_no_digest_export(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);p=root/'_retail_'/m.ref.MAIN_FILES['client_executable'];b=p.read_bytes();p.write_bytes(b'x'+b[1:])
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertEqual(r['components']['client_executable']['status'],'hash_mismatch');self.assertIsNone(r['components']['client_executable']['matched_public_ckey']);self.assertFalse(r['all_selected_components_match'])
 def test_missing_file_not_global_absence(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);(root/'_retail_'/m.ref.MAIN_FILES['client_loader']).unlink()
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertEqual(r['components']['client_loader']['status'],'not_found');self.assertFalse(r['whole_game_scanned'])
 def test_main_budget_allows_more_than_small_mode(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'file';p.write_bytes(bytes(4*1024*1024+1));r=m.blank();_,_=m.Reader(r,budget=m.BUDGET).file(p,5*1024*1024,digest=True);self.assertGreater(r['bytes_read'],4*1024*1024)
 def test_budget_and_expected_sizes(self):
  self.assertEqual(m.BUDGET,167772160);self.assertEqual(m.PER_FILE_LIMIT,134217728);self.assertLess(sum(max(v['size']for v in vals)for vals in m.ref.MAIN_COMPONENTS.values())+65536,m.BUDGET)
 def test_expired_deadline_refused(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'file';p.write_bytes(b'x')
   with self.assertRaises(m.Refused):m.Reader(m.blank(),budget=m.BUDGET,deadline=0).file(p,1,digest=True)
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);p=root/'_retail_'/m.ref.MAIN_FILES['client_executable'];q=root/'actual';p.rename(q);p.symlink_to(q)
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertEqual(r['error_kind'],'link_or_reparse');self.assertEqual(r['verified_components'],0)
 def test_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);p=root/'_retail_'/m.ref.MAIN_FILES['client_executable'];os.link(p,root/'other')
   with patch.object(m.ref,'MAIN_COMPONENTS',ref):r=m.assess(root)
   self.assertEqual(r['error_kind'],'not_regular_unshared')
 def test_change_between_stat_and_open_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,ref=self.fixture(t);original=m.Reader.file
   def read(reader,path,cap,digest=False):
    if digest and Path(path).name==m.ref.MAIN_FILES['client_executable']:Path(path).write_bytes(b'x')
    return original(reader,path,cap,digest)
   with patch.object(m.ref,'MAIN_COMPONENTS',ref),patch.object(m.Reader,'file',read):r=m.assess(root)
   self.assertEqual(r['error_kind'],'source_changed');self.assertEqual(r['verified_components'],0)
if __name__=='__main__':unittest.main()
