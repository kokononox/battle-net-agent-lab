import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import core
class FirewallErrorTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.base=Path(self.t.name);self.j=self.base/'session.json';i='a'*32
  core.atomic(self.j,{'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(self.base/'Wow.exe'),**core.ENDPOINTS[0]})
 def tearDown(self):self.t.cleanup()
 def call(self,result=None,error=None):
  with patch.object(core,'BASE',self.base),patch.dict(os.environ,{'SystemRoot':'C:\\Windows'}),patch.object(core.subprocess,'run',return_value=result,side_effect=error):return core.firewall('add',self.j)
 def error_report(self):return json.loads(next((self.base/'output').glob('firewall-error-*.json')).read_text())
 def test_structured_failure_preserves_exact_stage(self):
  result=subprocess.CompletedProcess([],3,json.dumps({'ok':False,'stage':'verify_persistent_rule','reason':'persistent_filter_mismatch','checks':{'protocol':False,'program':True},'hresult':-1}).encode(),b'private path')
  with self.assertRaisesRegex(RuntimeError,'firewall_add_failed_verify_persistent_rule'):self.call(result)
  self.assertEqual(self.error_report()['checks'],{'protocol':False,'program':True})
 def test_creation_rejection_is_not_readback_failure(self):
  r=subprocess.CompletedProcess([],3,b'{"ok":false,"stage":"create_rule","reason":"operation_failed","category":"PermissionDenied"}',b'')
  with self.assertRaisesRegex(RuntimeError,'failed_create_rule'):self.call(r)
  self.assertEqual(self.error_report()['category'],'PermissionDenied')
 def test_no_raw_paths_or_error_export(self):
  r=subprocess.CompletedProcess([],3,json.dumps({'ok':False,'stage':'create_rule','reason':'operation_failed','message':'C:\\Secret\\wow.exe','checks':{'secret':'password'}}).encode(),b'username-secret')
  with self.assertRaises(RuntimeError):self.call(r)
  text=next((self.base/'output').glob('*.json')).read_text();self.assertNotIn('Secret',text);self.assertNotIn('password',text);self.assertNotIn('username',text)
 def test_invalid_stdout_is_recorded(self):
  with self.assertRaisesRegex(RuntimeError,'powershell_output'):self.call(subprocess.CompletedProcess([],3,b'not json',b'private'))
  self.assertEqual(self.error_report()['reason'],'invalid_output')
 def test_timeout_is_recorded(self):
  with self.assertRaisesRegex(RuntimeError,'powershell_timeout'):self.call(error=subprocess.TimeoutExpired([],60))
  self.assertEqual(self.error_report()['reason'],'timeout')
 def test_launch_failure_is_recorded(self):
  with self.assertRaisesRegex(RuntimeError,'powershell_launch'):self.call(error=OSError('private path'))
 def test_success_no_error_file(self):
  result=self.call(subprocess.CompletedProcess([],0,b'{"ok":true,"rule_config_verified":true}',b''));self.assertTrue(result['ok']);self.assertFalse((self.base/'output').exists())
 def test_only_readback_retried_in_script(self):
  s=(Path(__file__).resolve().parents[1]/'app/firewall.ps1').read_text();self.assertEqual(s.count('New-NetFirewallRule '),1);self.assertIn('$attempt -lt 5',s);self.assertIn('$actualProtocol -eq $expectedNumber -or',s)
if __name__=='__main__':unittest.main()
