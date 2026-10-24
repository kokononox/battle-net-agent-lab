from pathlib import Path
import hashlib,json,shutil,sys,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'diagnostic081'))
import common
CFG={'url':'https://ufw-test.example/probe.php','address':'9.9.9.9'}
class SamePathBinding(unittest.TestCase):
 def fixture(self,root):
  (root/'runtime').mkdir()
  programs=[]
  for role,name in [('A','python.exe'),('B','pythonw.exe')]:
   p=root/'runtime'/name;p.write_bytes(role.encode());programs.append({'role':role,'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
  job=root/'private-state/coexistence-jobs/last';job.mkdir(parents=True)
  value={'schema':'unifiedfw-coexistence-result-1','read_only':False,'https_pacing':{},'restore_verified':True,'phases':[{'restored':True,'baseline_strict_equal':True}],'endpoint':dict(https_url=CFG['url'],address=CFG['address'],port=443)}
  (job/'result.json').write_text(json.dumps(value));(job/'request.json').write_text(json.dumps({'programs':programs}));return job,value,programs
 def test_same_paths_hashes_and_endpoint_required(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.fixture(root)
   with patch.object(common,'ROOT',root):r=common.previous_test(CFG)
   self.assertTrue(r['same_runtime_paths_as_latest_081_test']);self.assertTrue(r['previous_restoration_record_is_not_a_live_policy_check'])
 def test_different_executable_folder_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);job,v,p=self.fixture(root);p[0]['path']=str(root/'another/python.exe');(job/'request.json').write_text(json.dumps({'programs':p}))
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'paths_differ'):common.previous_test(CFG)
 def test_changed_executable_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.fixture(root);(root/'runtime/python.exe').write_bytes(b'changed')
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'hash_mismatch'):common.previous_test(CFG)
 def test_different_destination_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.fixture(root)
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'same_endpoint'):common.previous_test(dict(CFG,address='8.8.8.8'))
 def test_latest_unrestored_result_is_not_skipped_for_old_good_one(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);job,v,p=self.fixture(root);later=job.parent/'new';later.mkdir();v['restore_verified']=False;(later/'result.json').write_text(json.dumps(v))
   import os
   os.utime(later/'result.json',(2000000000,2000000000))
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'restore_not_verified'):common.previous_test(CFG)
 def test_missing_prior_test_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   with patch.object(common,'ROOT',Path(tmp)),self.assertRaisesRegex(ValueError,'no_previous_081'):common.previous_test(CFG)
 def test_wrong_base_manifest_fails_before_network(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'MANIFEST-SHA256.json').write_text('{}')
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'original_081_folder'):common.verify()
 def test_real_base_package_plus_addon_verifies_without_overwriting_any_base_file(self):
  # Local Linux filesystem integration only, not execution of Windows binaries.
  original=Path('/data/unified-firewall-0.8.1')
  if not original.is_dir():self.skipTest('original development fixture not available')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)/'081';shutil.copytree(original,root,ignore=shutil.ignore_patterns('__pycache__'))
   manifest={}
   for p in ROOT.rglob('*'):
    if p.is_file() and '__pycache__' not in p.parts and p.name!='DIAGNOSTIC081-SHA256.json':
     rel=p.relative_to(ROOT);self.assertFalse((root/rel).exists(),str(rel));dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);manifest[rel.as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
   (root/'DIAGNOSTIC081-SHA256.json').write_text(json.dumps(manifest))
   with patch.object(common,'ROOT',root):common.verify()
   # Tampering with an add-on file remains a refusal even when base is correct.
   (root/'diagnostic081/probe.py').write_text('changed')
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'package_changed'):common.verify()
if __name__=='__main__':unittest.main()
