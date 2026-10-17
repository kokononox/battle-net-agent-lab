"""Windows numeric error injection on Linux, not a real Windows fix proof."""
import contextlib,errno,io,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import local_update_review as r
import local_review_launcher as launch
import source_binding as b
sys.path.insert(0,str(Path(r.__file__).parent/'local_review_tests'))
from fixtures import Fixture,contents
SECRET='PRIVATE_USER_PATH_AND_MESSAGE'
def error(code=22,winerror=123):
 ex=OSError(code,SECRET,SECRET);ex.winerror=winerror;return ex

class SafeDiagnostics(unittest.TestCase):
 def test_errno_winerror_retained(self):
  q=r.public_error(error(),stage='bind_saved_checkpoint');self.assertEqual(q['errno'],22);self.assertEqual(q['winerror'],123)
 def test_private_exception_details_omitted(self):self.assertNotIn(SECRET,json.dumps(r.public_error(error())))
 def test_stage_whitelist(self):self.assertEqual(r.public_error(error(),stage=SECRET)['stage'],'unknown')
 def test_known_stage(self):self.assertEqual(r.public_error(error(),stage='publish_report_noreplace')['stage'],'publish_report_noreplace')
 def test_errno_type_not_coerced(self):
  ex=OSError();ex.errno=SECRET;ex.winerror=True;q=r.public_error(ex);self.assertNotIn('errno',q);self.assertNotIn('winerror',q)
 def test_non_os_error_no_os_codes(self):
  q=r.public_error(ValueError(SECRET));self.assertNotIn('errno',q);self.assertNotIn(SECRET,json.dumps(q))
 def test_binding_error_keeps_safe_code(self):self.assertEqual(r.public_error(b.BindingError('saved_file_fingerprint_changed'))['code'],'saved_file_fingerprint_changed')
 def test_runtime_values(self):q=r.public_error(error());self.assertEqual(len(q['python_version']),3);self.assertIn(q['platform'],('linux','win32','darwin','other'))
 def test_version_marker(self):self.assertEqual(r.public_error(error())['diagnostics_version'],'local-review-diag-2')
 def raised(self,module,source):
  ns={'__name__':module,'error':error}
  try:exec(compile(source,SECRET,'exec'),ns)
  except OSError as ex:return r.public_error(ex)
  self.fail('fixture did not raise')
 def test_safe_trace_excludes_filename_source_and_locals(self):
  q=self.raised('source_binding','def file():\n private_local="'+SECRET+'"\n raise error()\nfile()')
  self.assertNotIn(SECRET,json.dumps(q));self.assertTrue(any(x['function']=='file' for x in q['safe_trace']))
 def test_unlisted_module_trace_omitted(self):
  q=self.raised(SECRET,'raise error()');self.assertEqual(q['safe_trace'],[]);self.assertNotIn(SECRET,json.dumps(q))
 def test_stack_size_bounded(self):
  q=self.raised('source_binding','def file(n):\n if n:file(n-1)\n else:raise error()\nfile(30)');self.assertEqual(len(q['safe_trace']),12)
 def test_module_function_name_normalized(self):
  q=self.raised('source_binding','raise error()');self.assertEqual(q['safe_trace'][-1]['function'],'internal')
 def test_progress_rejects_unknown_phase(self):
  p=r.Progress()
  with self.assertRaises(b.BindingError):p.mark(SECRET)
  self.assertEqual(p.stage,'start')
 def test_validation_phase_before_any_io(self):
  p=r.Progress()
  with patch.object(b,'bind',side_effect=AssertionError('no IO')):
   with self.assertRaises(b.BindingError):r.review('unused','unused',object_limit=0,progress=p.mark)
  self.assertEqual(p.stage,'validate_arguments')
 def test_binding_oserror_phase(self):
  p=r.Progress()
  with patch.object(b,'bind',side_effect=error()):
   with self.assertRaises(OSError) as ex:r.review('unused','unused',progress=p.mark)
  q=r.public_error(ex.exception,stage=p.stage);self.assertEqual(q['stage'],'bind_saved_checkpoint');self.assertNotIn(SECRET,json.dumps(q))

class PhaseIntegration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.portable=Path(os.environ['REVIEW_PORTABLE']).resolve();cls.audit=cls.portable/'pinned_metadata'
  cls.metadata=b.load_metadata(cls.audit,b.Watch());cls.source=Path(os.environ['REVIEW_SOURCE_ARCHIVE']).read_bytes()
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root,self.metadata[2],self.source)
 def tearDown(self):self.temp.cleanup()
 def review(self,**kw):
  with patch.object(b,'load_metadata',return_value=self.metadata):return r.review(self.f.lab,self.audit,**kw)
 def test_success_phase_sequence_keeps_inputs_unchanged(self):
  stages=[];before=contents(self.root);q,_=self.review(progress=stages.append)
  self.assertEqual(q['actions'],{'full_download':1,'reuse':1});self.assertEqual(stages[0],'validate_arguments');self.assertEqual(stages[-1],'final_input_recheck');self.assertIn('verify_target_payloads',stages);self.assertEqual(contents(self.root),before)
 def test_metadata_error_phase(self):
  p=r.Progress()
  with patch.object(b,'load_metadata',side_effect=[self.metadata,error()]):
   with self.assertRaises(OSError):r.review(self.f.lab,self.audit,progress=p.mark)
  self.assertEqual(p.stage,'load_pinned_metadata')
 def test_payload_oserror_phase(self):
  p=r.Progress();before=contents(self.root)
  with patch.object(r.Reader,'verify',side_effect=error()):
   with self.assertRaises(OSError):self.review(progress=p.mark)
  self.assertEqual(p.stage,'verify_target_payloads');self.assertEqual(contents(self.root),before)
 def test_report_link_oserror_phase_and_cleanup(self):
  q,private=self.review();p=r.Progress();out=self.root/'out';before=contents(self.f.lab)
  with patch.object(r.os,'link',side_effect=error(errno.ENOTSUP,50)):
   with self.assertRaises(OSError) as ex:r.publish(self.f.lab,q,private,out,progress=p.mark)
  diagnostic=r.public_error(ex.exception,stage=p.stage);self.assertEqual(diagnostic['stage'],'publish_report_noreplace');self.assertEqual(diagnostic['winerror'],50)
  self.assertFalse((out/'LOCAL-UPDATE-REVIEW-to-share.json').exists());self.assertFalse(list(out.glob('*.pending')));self.assertEqual(contents(self.f.lab),before)
 def test_report_directory_oserror_phase(self):
  q,private=self.review();p=r.Progress()
  with patch.object(Path,'mkdir',side_effect=error()):
   with self.assertRaises(OSError):r.publish(self.f.lab,q,private,self.root/'out',progress=p.mark)
  self.assertEqual(p.stage,'create_report_directory')
 def test_report_write_oserror_phase_and_cleanup(self):
  q,private=self.review();p=r.Progress();out=self.root/'out'
  with patch.object(r.json,'dump',side_effect=error(13,5)):
   with self.assertRaises(OSError):r.publish(self.f.lab,q,private,out,progress=p.mark)
  self.assertEqual(p.stage,'write_pending_report');self.assertFalse(list(out.glob('*')))
 def fake_tk(self,choice):
  tk=types.ModuleType('tkinter');root=types.SimpleNamespace(withdraw=lambda:None,destroy=lambda:None);tk.Tk=lambda:root
  tk.filedialog=types.SimpleNamespace(askdirectory=lambda **kw:choice);tk.messagebox=types.SimpleNamespace()
  return {'tkinter':tk,'tkinter.filedialog':tk.filedialog,'tkinter.messagebox':tk.messagebox}
 def test_launcher_prints_safe_error_and_version(self):
  def fail(*args,**kw):kw['progress']('bind_saved_checkpoint');raise error()
  text=io.StringIO()
  with patch.dict(sys.modules,self.fake_tk(str(self.f.lab))),patch.object(r,'review',side_effect=fail),contextlib.redirect_stdout(text):code=launch.main()
  self.assertEqual(code,1);self.assertNotIn(SECRET,text.getvalue());self.assertIn('local-review-diag-2',text.getvalue())
  q=json.loads(next(x for x in text.getvalue().splitlines() if x.startswith('{')));self.assertEqual(q['stage'],'bind_saved_checkpoint');self.assertEqual(q['winerror'],123)
 def test_picker_cancel_does_no_review(self):
  text=io.StringIO()
  with patch.dict(sys.modules,self.fake_tk('')),patch.object(r,'review',side_effect=AssertionError('no read')),contextlib.redirect_stdout(text):self.assertEqual(launch.main(),0)
 def test_old_python_guard(self):
  with patch.object(sys,'version_info',(3,9,0)),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(launch.main(),1)
if __name__=='__main__':unittest.main()
