import os,sys,tempfile,unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import disk_prepare as d
import classic_install as c
import probe

class DiskPrepareTests(unittest.TestCase):
 def env(self):
  return dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',AGENT_INTERFACE_ONCE=probe.APPROVAL,CLASSIC_INSTALL_ONCE=c.APPROVAL,CLASSIC_DISK_PREPARE_ONCE=d.ONCE,SystemDrive='C:')
 def test_guard_every_environment_field(self):
  e=self.env();self.assertTrue(d.approved(e,'win32'))
  for key in e:
   bad=e.copy();bad[key]='wrong';self.assertFalse(d.approved(bad,'win32'),key)
  self.assertFalse(d.approved(e,'linux'))
 def test_no_io_without_approval(self):
  with patch.object(d.shutil,'disk_usage',side_effect=AssertionError('io')),patch.object(d.shutil,'rmtree',side_effect=AssertionError('delete')):
   self.assertEqual(d.prepare({},'win32')['status'],'environment_refused')
 def test_threshold_unchanged(self):self.assertEqual(c.MIN_FREE,40*1024**3);self.assertGreater(d.GOAL,c.MIN_FREE)
 def test_literal_allowlist(self):
  self.assertEqual(len(d.CANDIDATES),5)
  for label,path in d.CANDIDATES:
   p=PureWindowsPath(path);self.assertEqual(p.drive,'C:');self.assertNotIn('..',p.parts)
   self.assertNotIn('Python',path);self.assertNotIn('Users',p.parts)
 def test_enough_space_no_deletion(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=d.GOAL)),patch.object(d.shutil,'rmtree')as rm:
   r=d.prepare(self.env(),'win32')
  rm.assert_not_called();self.assertEqual(r['status'],'goal_met');self.assertEqual(r['removed'],[])
 def test_stop_as_soon_as_goal_met(self):
  readings=iter([d.GOAL-1,d.GOAL-1,d.GOAL,d.GOAL])
  with patch.object(d.shutil,'disk_usage',side_effect=lambda _:SimpleNamespace(free=next(readings))),patch.object(d,'safe_tree',return_value=True),patch.object(d.shutil,'rmtree')as rm:
   r=d.prepare(self.env(),'win32')
  self.assertEqual(rm.call_count,1);self.assertEqual(r['removed'],['android-sdk'])
 def test_unsafe_paths_never_deleted(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),patch.object(d,'safe_tree',return_value=False),patch.object(d.shutil,'rmtree')as rm:
   r=d.prepare(self.env(),'win32')
  rm.assert_not_called();self.assertEqual(r['status'],'space_still_low');self.assertEqual(len(r['skipped']),5)
 def test_locked_tree_no_expanded_fallback(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),patch.object(d,'safe_tree',return_value=True),patch.object(d.shutil,'rmtree',side_effect=PermissionError)as rm:
   r=d.prepare(self.env(),'win32')
  self.assertEqual(rm.call_count,5);self.assertEqual(r['removed'],[])
 def test_real_tree_and_symlink_refusal(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'tool';p.mkdir();(p/'file').write_text('test');self.assertTrue(d.safe_tree(p))
   (p/'link').symlink_to(p/'file');self.assertFalse(d.safe_tree(p));(p/'link').unlink()
   link=Path(temp)/'parent-link';link.symlink_to(p,target_is_directory=True)
   self.assertFalse(d.safe_tree(link));self.assertFalse(d.safe_tree(link/'subdir'))
 def test_windows_reparse_attribute(self):
  fake=SimpleNamespace(lstat=lambda:SimpleNamespace(st_mode=stat_mode(),st_file_attributes=0x400))
  self.assertTrue(d.reparse(fake))

def stat_mode():return 0o40755
if __name__=='__main__':unittest.main()
