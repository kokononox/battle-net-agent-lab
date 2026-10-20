import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from cleanup_capture import cleanup
import observe
from pml_read import analyze,PmlError

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.base=Path(self.t.name);self.raw=self.base/'captures'/('a'*32);self.raw.mkdir(parents=True)
        self.p=self.raw/'capture.pml';self.p.write_bytes(b'raw')
    def tearDown(self):self.t.cleanup()
    def test_delete_only_own(self):
        (self.raw/'keep.json').write_text('{}');(self.raw/'other.pml').write_bytes(b'keep')
        r=cleanup(self.raw,self.base,False);self.assertEqual((r['deleted_files'],r['deleted_bytes']),(1,3));self.assertFalse(self.p.exists());self.assertTrue((self.raw/'other.pml').exists());self.assertTrue((self.raw/'keep.json').exists())
    def test_procmon_present_preserves(self):
        r=cleanup(self.raw,self.base,True);self.assertTrue(self.p.exists());self.assertIn('retained',r['status'])
    def test_outside_session_preserves(self):
        r=cleanup(self.base,self.base,False);self.assertTrue(self.p.exists());self.assertIn('not_trusted',r['status'])
    def test_non_uuid_session_preserves(self):
        q=self.raw.with_name('user-folder');self.raw.rename(q);r=cleanup(q,self.base,False);self.assertTrue((q/'capture.pml').exists());self.assertIn('not_trusted',r['status'])
    def test_split_files(self):
        for n in ['capture-1.pml','capture_2.pml','capture3.pml']:(self.raw/n).write_bytes(b'x')
        self.assertEqual(cleanup(self.raw,self.base,False)['deleted_files'],4)
    def test_locked_file_retained(self):
        with patch.object(Path,'unlink',side_effect=PermissionError):r=cleanup(self.raw,self.base,False)
        self.assertEqual(r['status'],'some_files_retained');self.assertTrue(self.p.exists())
    def test_symlink_file_preserves_target(self):
        self.p.unlink();target=self.base/'private';target.write_bytes(b'keep');self.p.symlink_to(target)
        r=cleanup(self.raw,self.base,False);self.assertEqual(target.read_bytes(),b'keep');self.assertEqual(r['status'],'some_files_retained')
    def test_symlink_session_preserves_target(self):
        target=self.base/'elsewhere';self.raw.rename(target);self.raw.symlink_to(target,target_is_directory=True)
        r=cleanup(self.raw,self.base,False);self.assertTrue((target/'capture.pml').exists());self.assertIn('not_trusted',r['status'])
    def test_none(self):self.assertEqual(cleanup(None,self.base,False)['deleted_files'],0)
    def test_report_before_delete(self):
        with patch.object(observe,'BASE',self.base),patch.object(observe,'RAW',self.raw),patch.object(observe,'procmon_pids',return_value=set()):
            observe.finish({'status':'analysis_inconclusive'})
        reports=list((self.base/'output').glob('*.json'));self.assertEqual(len(reports),1)
        r=json.loads(reports[0].read_text());self.assertEqual(r['raw_cleanup']['deleted_files'],1);self.assertFalse(self.p.exists())
    def test_report_save_failure_preserves(self):
        with patch.object(observe,'RAW',self.raw),patch.object(observe,'save',side_effect=OSError):
            with self.assertRaises(OSError):observe.finish({})
        self.assertTrue(self.p.exists())
    def test_procmon_check_failure_preserves(self):
        with patch.object(observe,'BASE',self.base),patch.object(observe,'RAW',self.raw),patch.object(observe,'procmon_pids',side_effect=OSError):observe.finish({})
        self.assertTrue(self.p.exists())
    def test_report_finalize_failure_keeps_initial(self):
        with patch.object(observe,'BASE',self.base),patch.object(observe,'RAW',self.raw),patch.object(observe,'procmon_pids',return_value=set()),patch.object(observe.os,'replace',side_effect=OSError):observe.finish({})
        self.assertTrue(next((self.base/'output').glob('*.json')).is_file())
    def test_soft_limit_consistent(self):
        s=(Path(observe.__file__)).read_text();self.assertIn('soft_raw_budget_bytes=1024**3',s);self.assertIn('size>=1024**3',s)
        self.assertIn("'/Runtime','20'",s);self.assertNotIn('/SaveAs',s)

if __name__=='__main__':unittest.main()
