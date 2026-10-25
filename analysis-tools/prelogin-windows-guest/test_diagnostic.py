import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import diagnostic_entry as d
class Tests(unittest.TestCase):
 def invoke(self,exc,stage='validate'):
  with tempfile.TemporaryDirectory() as tmp:
   cwd=os.getcwd();os.chdir(tmp)
   try:
    with patch.dict(os.environ,{'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123'}),patch.object(d.core,'STAGE',stage),patch.object(d.core,'main',side_effect=exc):result=d.run()
    r=json.loads(Path('output/windows-guest-preparation-diagnostic.json').read_text());f=d.core.validate(json.loads(Path('output/windows-guest-preparation.json').read_text()))
    return result,r,f
   finally:os.chdir(cwd)
 def test_validation_reason(self):
  code,r,f=self.invoke(ValueError('ready_gate'));self.assertEqual(code,1);self.assertEqual(r['reason'],'ready_gate');self.assertTrue(r['fallback_written']);self.assertEqual(f['status'],'stopped')
 def test_no_exception_text(self):
  _,r,_=self.invoke(RuntimeError('PRIVATE_UUID_EXAMPLE'));self.assertNotIn('PRIVATE',json.dumps(r));self.assertEqual(r['exception_kind'],'other')
 def test_guard_rejected(self):self.assertEqual(self.invoke(SystemExit('owned_ephemeral_host_once_required'),'guard')[1]['reason'],'guard_rejected')
 def test_no_foreign_stage(self):self.assertEqual(self.invoke(ValueError('images'),'private_path')[1]['stage'],'entry')
 def test_no_arbitrary_fields(self):
  _,r,_=self.invoke(ValueError('images'));r['raw']='private';self.assertRaises(ValueError,d.validate,r)
 def test_no_boot_stage(self):
  _,r,_=self.invoke(ValueError('images'));r['stage']='windows_booted';self.assertRaises(ValueError,d.validate,r)
