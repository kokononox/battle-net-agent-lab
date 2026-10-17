"""Linux tests with explicit Windows rename-contract model; not native Windows."""
import errno,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import local_update_review as r
import source_binding as b
sys.path.insert(0,str(Path(r.__file__).parent/'local_review_tests'))
from fixtures import Fixture,contents
LINK=os.link

def win_error(code=1):
 ex=OSError(errno.EINVAL,'PRIVATE Windows operation failure');ex.winerror=code;return ex

def modeled_windows_rename(src,dst):
 # Test-only no-replace model using Linux hardlinks. Production Windows calls
 # Python os.rename directly; this model does not test the Windows filesystem.
 LINK(src,dst);Path(src).unlink()

class Dispatch(unittest.TestCase):
 def test_windows_uses_rename_not_hardlink(self):
  with patch.object(r.sys,'platform','win32'),patch.object(r.os,'rename') as rename,patch.object(r.os,'link',side_effect=AssertionError('hardlink forbidden')):
   r.publish_report_noreplace('گزارش.pending','گزارش.json');rename.assert_called_once_with('گزارش.pending','گزارش.json')
 def test_posix_keeps_link_not_overwriting_rename(self):
  with patch.object(r.sys,'platform','linux'),patch.object(r.os,'link') as link,patch.object(r.os,'rename',side_effect=AssertionError('POSIX rename forbidden')):
   r.publish_report_noreplace('a','b');link.assert_called_once_with('a','b')
 def test_windows_error_is_not_retried_or_fallen_back(self):
  ex=win_error()
  with patch.object(r.sys,'platform','win32'),patch.object(r.os,'rename',side_effect=ex) as rename,patch.object(r.os,'link',side_effect=AssertionError('no fallback')),patch.object(r.os,'replace',side_effect=AssertionError('no overwrite')):
   with self.assertRaises(OSError) as caught:r.publish_report_noreplace('a','b')
   self.assertIs(caught.exception,ex);self.assertEqual(rename.call_count,1)
 def test_windows_existing_destination_error_propagates(self):
  with patch.object(r.sys,'platform','win32'),patch.object(r.os,'rename',side_effect=FileExistsError(errno.EEXIST,'exists')),patch.object(r.os,'link',side_effect=AssertionError('no fallback')):
   with self.assertRaises(FileExistsError):r.publish_report_noreplace('a','b')
 def test_version_marker(self):self.assertEqual(r.DIAGNOSTICS_VERSION,'local-review-diag-4')

class WindowsPublication(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.audit=Path(os.environ['REVIEW_PORTABLE']).resolve()/'pinned_metadata';cls.metadata=b.load_metadata(cls.audit,b.Watch());cls.source=Path(os.environ['REVIEW_SOURCE_ARCHIVE']).read_bytes()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root,self.metadata[2],self.source)
  with patch.object(b,'load_metadata',return_value=self.metadata):self.report,self.private=r.review(self.f.lab,self.audit)
  self.before=contents(self.f.lab);self.out=self.root/'گزارش-output';self.final=self.out/'LOCAL-UPDATE-REVIEW-to-share.json';self.progress=r.Progress()
 def tearDown(self):self.temp.cleanup()
 def publish(self,rename=modeled_windows_rename,out=None):
  with patch.object(r.sys,'platform','win32'),patch.object(r.os,'rename',side_effect=rename),patch.object(r.os,'link',side_effect=AssertionError('production hardlink forbidden')),patch.object(r.os,'replace',side_effect=AssertionError('replace forbidden')):
   return r.publish(self.f.lab,self.report,self.private,out or self.out,progress=self.progress.mark)
 def test_windows_success_while_hardlinks_forbidden(self):
  self.assertEqual(self.publish(),self.out);self.assertEqual(json.loads(self.final.read_text()),self.report);self.assertEqual(list(self.out.iterdir()),[self.final]);self.assertEqual(contents(self.f.lab),self.before);self.assertEqual(self.progress.stage,'postpublication_recheck')
 def test_windows_existing_racing_destination_untouched(self):
  def race(src,dst):Path(dst).write_bytes(b'KEEP');modeled_windows_rename(src,dst)
  with self.assertRaises(FileExistsError):self.publish(race)
  self.assertEqual(self.final.read_bytes(),b'KEEP');self.assertFalse(list(self.out.glob('*.pending')));self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_report_directory_race_rejected(self):
  self.out.mkdir();(self.out/'KEEP').write_bytes(b'KEEP')
  with self.assertRaises(b.BindingError):self.publish()
  self.assertEqual((self.out/'KEEP').read_bytes(),b'KEEP');self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_rename_error_keeps_safe_diagnostics_and_cleans_pending(self):
  def fail(src,dst):raise win_error()
  with self.assertRaises(OSError) as caught:self.publish(fail)
  q=r.public_error(caught.exception,stage=self.progress.stage);self.assertEqual(q['stage'],'publish_report_noreplace');self.assertEqual(q['winerror'],1);self.assertNotIn('PRIVATE',json.dumps(q));self.assertFalse(list(self.out.iterdir()));self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_change_after_rename_removes_published_report(self):
  def change(src,dst):modeled_windows_rename(src,dst);self.f.archive.write_bytes(self.source+b'x')
  with self.assertRaises(b.BindingError):self.publish(change)
  self.assertFalse(self.final.exists());self.assertFalse(list(self.out.glob('*.pending')));self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_sidecar_after_rename_removes_report(self):
  def change(src,dst):modeled_windows_rename(src,dst);Path(str(self.f.plan)+'-journal').write_bytes(b'x')
  with self.assertRaises(b.BindingError):self.publish(change)
  self.assertFalse(self.final.exists());self.assertFalse(list(self.out.glob('*.pending')))
 def test_windows_changed_input_prevents_rename(self):
  self.f.archive.write_bytes(self.source+b'x')
  with self.assertRaises(b.BindingError):self.publish(lambda *args:self.fail('must not rename'))
  self.assertFalse(self.out.exists())
 def test_windows_lab_output_still_forbidden(self):
  with self.assertRaises(b.BindingError):self.publish(out=self.f.lab/'report')
  self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_storage_output_still_forbidden(self):
  with self.assertRaises(b.BindingError):self.publish(out=self.f.storage/'report')
  self.assertEqual(contents(self.f.lab),self.before)
 def test_windows_game_tree_output_still_forbidden(self):
  game=self.root/'game';game.mkdir();(game/'.build.info').write_bytes(b'KEEP')
  with self.assertRaises(b.BindingError):self.publish(out=game/'report')
  self.assertEqual((game/'.build.info').read_bytes(),b'KEEP');self.assertFalse((game/'report').exists())
 def test_original_hardlink_error_signature_reproduced_on_linux(self):
  with patch.object(r.sys,'platform','linux'),patch.object(r.os,'link',side_effect=win_error()):
   with self.assertRaises(OSError) as caught:r.publish(self.f.lab,self.report,self.private,self.out,progress=self.progress.mark)
  q=r.public_error(caught.exception,stage=self.progress.stage);self.assertEqual((q['errno'],q['winerror'],q['stage']),(22,1,'publish_report_noreplace'));self.assertFalse(list(self.out.iterdir()));self.assertEqual(contents(self.f.lab),self.before)
if __name__=='__main__':unittest.main()
