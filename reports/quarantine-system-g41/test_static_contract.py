"""Offline source-contract checks, not Windows runtime acceptance."""
import ast,json,os,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]/'analysis-tools/quarantine-system-g41'
class StaticContracts(unittest.TestCase):
 def test_clean_environment_keeps_native_execution_without_credentials(self):
  tree=ast.parse((ROOT/'coordinator.py').read_text())
  selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='clean_env' or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='KEEP' for t in n.targets)]
  scope={'os':os};exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),'environment','exec'),scope)
  sample={'SystemRoot':'C:\\Windows','ProgramData':'C:\\ProgramData','TEMP':'C:\\Temp','GITHUB_TOKEN':'secret','ACTIONS_RUNTIME_TOKEN':'secret','UNRELATED_SECRET':'secret','PATHEXT':'.UNTRUSTED'}
  with patch.dict(os.environ,sample,clear=True):env=scope['clean_env']()
  self.assertEqual(env,{'SystemRoot':'C:\\Windows','ProgramData':'C:\\ProgramData','TEMP':'C:\\Temp','PATHEXT':'.COM;.EXE;.BAT;.CMD'})
 def test_recovery_terminates_job_before_import(self):
  s=(ROOT/'recovery.py').read_text();self.assertLess(s.index('n.end_job(job)'),s.index("gate(c,'Restore')"))
  self.assertIn("result['job_active_zero']=n.active(job)==0",s)
 def test_error_is_real_abrupt_exit(self):
  s=(ROOT/'coordinator.py').read_text();self.assertIn("if c['mode']=='error':os._exit(23)",s)
 def test_no_upstream_on_quarantine_endpoint(self):
  t=ast.parse((ROOT/'quarantine_handler.py').read_text())
  self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {'connect','connect_ex','create_connection','urlopen'} for n in ast.walk(t)))
 def test_backup_and_import_require_integer_success(self):
  s=(ROOT/'Gate.ps1').read_text();self.assertIn('$script:ExportCode -isnot [int]',s);self.assertIn('$script:BackupLength -lt 100',s)
  self.assertIn("if($LASTEXITCODE -isnot [int] -or $LASTEXITCODE -ne 0){throw 'import_failed'}",s)
  self.assertLess(s.index("'gate-armed.json'"),s.index('|Disable-NetFirewallRule'))
if __name__=='__main__':unittest.main()
