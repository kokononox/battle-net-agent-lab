import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from model import *
from validate_report import decode
class Gates(unittest.TestCase):
 def env(self):return dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/'+BRANCH,GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_MINIMAL_INSTALL=APPROVAL,BNET_CASE=CASE,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
 def report(self):return blank(self.env())
 def success(self):
  r=self.report();r.update(status='installed_by_defined_gate',phase='complete',target_launched=True,native_ui_gate=True,cleanup_attempted=True,samples=1,install_checks={k:True for k in CHECKS},installer=dict(sha256=SETUP_SHA,bytes=SETUP_BYTES,signature_accepted=True,matches_pin=True),client_binaries=[dict(kind=k,sha256='b'*64,bytes=123,signature_accepted=True) for k in ('launcher','client')]);return r
 def test_guard(self):
  e=self.env();self.assertTrue(authorized(e,'win32'))
  for k in e:
   if k in ('GITHUB_SHA','GITHUB_RUN_ID'):continue
   with self.subTest(key=k):
    x=e.copy();x[k]='wrong';self.assertFalse(authorized(x,'win32'))
  self.assertFalse(authorized(e,'linux'))
 def test_blank_valid(self):validate(self.report())
 def test_success(self):validate(self.success())
 def test_each_missing_success_check(self):
  for k in CHECKS:
   r=self.success();r['install_checks'][k]=False
   with self.subTest(key=k),self.assertRaises(ValueError):validate(r)
 def test_nonbool_checks(self):
  for k in CHECKS:
   r=self.success();r['install_checks'][k]=1
   with self.assertRaises(ValueError):validate(r)
 def test_binary_evidence_required(self):
  r=self.success();r['client_binaries']=[]
  with self.assertRaises(ValueError):validate(r)
 def test_launch_pin(self):
  for field in ('matches_pin','signature_accepted'):
   r=self.success();r['installer'][field]=False
   with self.assertRaises(ValueError):validate(r)
 def test_scope_claims_rejected(self):
  for k in ('login_attempted','game_download_requested','raw_payloads_exported','all_processes_observed','all_network_observed','necessity_tested','telemetry_blocked'):
   r=self.report();r[k]=True
   with self.assertRaises(ValueError):validate(r)
 def test_ui_signal_scope(self):
  r=self.report();r['ui_signal_seen']['raw_text']='forbidden'
  with self.assertRaises(ValueError):validate(r)
 def test_probe_cap(self):
  r=self.report();r['native_options_probes']=31
  with self.assertRaises(ValueError):validate(r)
 def test_extra_raw_field(self):
  r=self.report();r['UserUUID']='not allowed'
  with self.assertRaises(ValueError):validate(r)
 def test_private_address(self):
  r=self.report();r['public_endpoints']=[dict(process_name='agent.exe',ip='192.168.1.1',port=443,samples=1)]
  with self.assertRaises(ValueError):validate(r)
 def test_duplicate_json(self):
  with self.assertRaises(ValueError):decode(b'{"schema":1,"schema":2}')
 def test_action_without_launch(self):
  r=self.report();r['language_attempted']=True
  with self.assertRaises(ValueError):validate(r)
 def test_unapproved_platform_no_files(self):
  if sys.platform=='win32':self.skipTest('Linux refusal test')
  with tempfile.TemporaryDirectory() as d:
   r=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'run_case.py')],cwd=d,env=self.env(),capture_output=True)
   self.assertNotEqual(r.returncode,0);self.assertFalse(list(Path(d).iterdir()))
if __name__=='__main__':unittest.main()
