import copy,os,sys,tempfile,unittest
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
  with patch.object(d.shutil,'disk_usage',side_effect=AssertionError('io')),patch.object(d,'remove_tree',side_effect=AssertionError('delete')):
   self.assertEqual(d.prepare({},'win32')['status'],'environment_refused')
 def test_threshold_unchanged(self):self.assertEqual(c.MIN_FREE,40*1024**3);self.assertGreater(d.GOAL,c.MIN_FREE)
 def test_literal_allowlist(self):
  self.assertEqual(len(d.CANDIDATES),8)
  self.assertTrue(d.CANDIDATES[5][1].endswith(r'Enterprise\VC\Tools\MSVC'))
  for label,path in d.CANDIDATES:
   p=PureWindowsPath(path);self.assertEqual(p.drive,'C:');self.assertNotIn('..',p.parts)
   self.assertNotIn('Python',path);self.assertNotIn('Users',p.parts);self.assertNotIn('Windows',p.parts)
 def test_enough_space_no_deletion(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=d.GOAL)),patch.object(d,'remove_tree')as rm:
   r=d.prepare(self.env(),'win32')
  rm.assert_not_called();self.assertEqual(r['status'],'goal_met');self.assertEqual(r['attempts'],[])
 def test_stop_as_soon_as_goal_met(self):
  readings=iter([d.GOAL-1,d.GOAL-1,d.GOAL,d.GOAL])
  with patch.object(d.shutil,'disk_usage',side_effect=lambda _:SimpleNamespace(free=next(readings))),patch.object(d,'inspect_tree',return_value=('safe',1,10)),patch.object(d,'remove_tree')as rm:
   r=d.prepare(self.env(),'win32')
  self.assertEqual(rm.call_count,1);self.assertEqual(r['attempts'][0]['outcome'],'removed')
 def test_unsafe_paths_never_deleted(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),patch.object(d,'inspect_tree',return_value=('ancestor_reparse',0,0)),patch.object(d,'remove_tree')as rm:
   r=d.prepare(self.env(),'win32')
  rm.assert_not_called();self.assertEqual(r['status'],'space_still_low');self.assertEqual(len(r['attempts']),8)
 def test_locked_tree_no_expanded_fallback(self):
  with patch.object(d.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),patch.object(d,'inspect_tree',return_value=('safe',1,10)),patch.object(d,'remove_tree',side_effect=PermissionError)as rm:
   r=d.prepare(self.env(),'win32')
  self.assertEqual(rm.call_count,8);self.assertTrue(all(a['outcome']=='io_refused'for a in r['attempts']))
 def test_real_tree_and_symlink_refusal(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'tool';p.mkdir();(p/'file').write_text('test');self.assertEqual(d.inspect_tree(p),('safe',1,4))
   (p/'link').symlink_to(p/'file');self.assertEqual(d.inspect_tree(p)[0],'tree_reparse');(p/'link').unlink()
   link=Path(temp)/'parent-link';link.symlink_to(p,target_is_directory=True)
   self.assertEqual(d.inspect_tree(link)[0],'ancestor_reparse');self.assertEqual(d.inspect_tree(link/'subdir')[0],'ancestor_reparse')
 def test_windows_reparse_attribute(self):
  fake=SimpleNamespace(lstat=lambda:SimpleNamespace(st_mode=0o40755,st_file_attributes=0x400))
  self.assertTrue(d.reparse(fake))
 def test_missing_and_not_directory(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'missing';self.assertEqual(d.inspect_tree(p)[0],'missing');p.write_bytes(b'x');self.assertEqual(d.inspect_tree(p)[0],'not_directory')
 def test_bounded_scan(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t);(p/'a').touch();(p/'b').touch()
   with patch.object(d,'MAX_ENTRIES',1):self.assertEqual(d.inspect_tree(p)[0],'scan_limit')
   tick=iter([0,121]);self.assertEqual(d.inspect_tree(p,clock=lambda:next(tick))[0],'scan_limit')
 def test_walk_error_not_silently_ignored(self):
  with tempfile.TemporaryDirectory()as t:
   def walk(*args,**kw):kw['onerror'](PermissionError());return []
   with patch.object(d.os,'walk',side_effect=walk):self.assertEqual(d.inspect_tree(Path(t))[0],'io_refused')
 def test_report_rejects_extras_and_wrong_threshold(self):
  r=d.blank(self.env());d.validate(r)
  for key,value in [('raw_path','private'),('goal_bytes',1),('system_free_after_bytes',True),('source_commit','wrong')]:
   bad=copy.deepcopy(r);bad[key]=value
   with self.assertRaises(ValueError,msg=key):d.validate(bad)
 def test_report_rejects_unapproved_labels_and_false_goal(self):
  r=d.blank(self.env());r['status']='space_still_low';r['attempts']=[dict(tool='Users',outcome='removed',entries=1,logical_bytes=1)]
  with self.assertRaises(ValueError):d.validate(r)
  r=d.blank(self.env());r['status']='goal_met'
  with self.assertRaises(ValueError):d.validate(r)
 def test_readonly_retry_confined_to_tree(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp)/'root';root.mkdir();child=root/'file';child.write_bytes(b'x')
   callbacks=[]
   def rm(path,**kw):callbacks.append(kw['onexc'])
   with patch.object(d.shutil,'rmtree',side_effect=rm):d.remove_tree(root)
   called=[]
   callbacks[0](lambda p:called.append(p),child,PermissionError())
   self.assertEqual(called,[child])
   with self.assertRaises(ValueError):callbacks[0](lambda p:called.append(p),Path(temp)/'outside',PermissionError())
   with self.assertRaises(OSError):callbacks[0](lambda p:called.append(p),child,OSError())
if __name__=='__main__':unittest.main()
