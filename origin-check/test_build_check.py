import hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import build_check as b
class BuildCheck(unittest.TestCase):
 def fixture(self,root):
  root=Path(root);(root/'_retail_/Utils').mkdir(parents=True);(root/'Data/data').mkdir(parents=True)
  (root/'.build.info').write_text('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Product!STRING:0|Private!STRING:0\n1|'+b.ref.BUILD_KEY+'|'+b.ref.VERSION+'|wow|NEVER_EXPORT\n')
  data={k:('synthetic-'+k).encode()for k in b.ref.FILES}
  for k,value in data.items():(root/'_retail_/Utils'/b.ref.FILES[k]).write_bytes(value)
  expected={k:[dict(size=len(v),ckey=hashlib.md5(v).hexdigest())]for k,v in data.items()}
  return root,expected
 def test_two_components_verified(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t)
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertTrue(r['active_build_matched']);self.assertEqual(r['verified_components'],2);self.assertTrue(r['all_selected_components_match']);self.assertFalse(r['whole_game_scanned']);self.assertFalse(r['archive_files_read']);self.assertNotIn('NEVER_EXPORT',json.dumps(r));self.assertNotIn(str(root),json.dumps(r))
 def test_wrong_build_refused_before_component_reads(self):
  with tempfile.TemporaryDirectory()as t:
   root,_=self.fixture(t);p=root/'.build.info';p.write_text(p.read_text().replace(b.ref.VERSION,'12.1.5.70575'));r=b.assess(root);self.assertEqual(r['error_kind'],'build_mismatch');self.assertEqual(r['verified_components'],0)
 def test_same_size_mutation_not_accepted_or_exported(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);p=root/'_retail_/Utils'/b.ref.FILES['voice_proxy'];data=p.read_bytes();p.write_bytes(b'x'+data[1:])
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual(r['components']['voice_proxy']['status'],'hash_mismatch');self.assertIsNone(r['components']['voice_proxy']['matched_public_ckey']);self.assertFalse(r['all_selected_components_match'])
 def test_missing_component_not_absence_of_watermark(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);(root/'_retail_/Utils'/b.ref.FILES['voice_proxy']).unlink()
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual(r['components']['voice_proxy']['status'],'not_found');self.assertFalse(r['copy_origin_proven'])
 def test_wrong_size_not_hashed(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);p=root/'_retail_/Utils'/b.ref.FILES['voice_proxy'];p.write_bytes(b'x');info=(root/'.build.info').stat().st_size
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual(r['components']['voice_proxy']['status'],'size_not_in_reference');self.assertEqual(r['bytes_read'],info+expected['exception_handler'][0]['size'])
 def test_direct_data_and_retail_paths(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t)
   with patch.object(b.ref,'COMPONENTS',expected):
    self.assertTrue(b.assess(root/'Data/data')['all_selected_components_match']);self.assertTrue(b.assess(root/'_retail_')['all_selected_components_match'])
 def test_oversized_metadata_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,_=self.fixture(t);(root/'.build.info').write_bytes(bytes(65537));r=b.assess(root);self.assertEqual(r['error_kind'],'file_size_limit')
 def test_read_budget_not_raised(self):
  r=b.blank();r['bytes_read']=b.BUDGET
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'data';p.write_bytes(b'x')
   with self.assertRaises(b.Refused):b.Reader(r).file(p,1)
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);p=root/'_retail_/Utils'/b.ref.FILES['voice_proxy'];other=root/'original';p.rename(other);p.symlink_to(other)
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual(r['error_kind'],'link_or_reparse')
 def test_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);p=root/'_retail_/Utils'/b.ref.FILES['voice_proxy'];os.link(p,root/'second_link')
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual(r['error_kind'],'not_regular_unshared')
 def test_changed_source_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,_=self.fixture(t);p=root/'.build.info';r=b.blank()
   with patch.object(b,'fingerprint',side_effect=[('old',),('new',)]):
    with self.assertRaises(b.Refused):b.Reader(r).file(p,65536)
 def test_ambiguous_active_retail_refused(self):
  with tempfile.TemporaryDirectory()as t:
   root,_=self.fixture(t);p=root/'.build.info';lines=p.read_text().splitlines();p.write_text('\n'.join(lines+[lines[1]])+'\n');r=b.assess(root);self.assertEqual(r['error_kind'],'active_retail_build_ambiguous')
 def test_reference_budget_and_keys(self):
  import re
  self.assertTrue(all(re.fullmatch('[0-9a-f]{32}',v['ckey'])for a in b.ref.COMPONENTS.values()for v in a));self.assertLess(sum(max(v['size']for v in a)for a in b.ref.COMPONENTS.values())+65536,b.BUDGET);self.assertEqual(b.ref.VERSION,'12.1.5.70448')
 def test_metadata_columns_not_rewritten_or_exposed(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);before=(root/'.build.info').read_bytes()
   with patch.object(b.ref,'COMPONENTS',expected):r=b.assess(root)
   self.assertEqual((root/'.build.info').read_bytes(),before);self.assertFalse(r['game_files_written']);self.assertFalse(r['network_requested']);self.assertFalse(r['client_executable_checked'])
 def test_changed_metadata_invalidates_positive_results(self):
  with tempfile.TemporaryDirectory()as t:
   root,expected=self.fixture(t);original=b.Reader.file
   def reader(reader,path,cap,digest=False):
    value=original(reader,path,cap,digest)
    if digest and Path(path).name==b.ref.FILES['exception_handler']:
     info=root/'.build.info';info.write_bytes(info.read_bytes()+b'\n')
    return value
   with patch.object(b.ref,'COMPONENTS',expected),patch.object(b.Reader,'file',reader):r=b.assess(root)
   self.assertEqual(r['error_kind'],'source_changed');self.assertEqual(r['verified_components'],0);self.assertFalse(r['all_selected_components_match']);self.assertTrue(all(c['matched_public_ckey']is None for c in r['components'].values()))
if __name__=='__main__':unittest.main()
