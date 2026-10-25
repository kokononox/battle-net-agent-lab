import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from model import *
from validate_report import decode
class Gates(unittest.TestCase):
 def env(self):return dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/'+BRANCH,GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_MINIMAL_INSTALL=APPROVAL,BNET_CASE=CASE,BNET_REPLICA='r1',GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
 def report(self):return blank(self.env())
 def success(self,replica='r1'):
  r=blank(dict(self.env(),BNET_REPLICA=replica));
  if POLICIES[replica][1]:r['hosts'].update(backup_created=True,override_written=True,resolver_verified=True,verification_checks=3,flush_exit_code=0,restore_flush_exit_code=0,restore_attempted=True,restored=True)
  r.update(status='installed_by_defined_gate',phase='complete',target_launched=True,started_at='2026-10-25T02:00:00Z',ended_at='2026-10-25T02:01:00Z',registry_version_state='missing',last_sample_process_names=['battle.net.exe'],ui_signal_seen={k:(k=='account') for k in UI_KEYS},native_ui_gate=True,cleanup_attempted=True,samples=1,install_checks={k:True for k in CHECKS},installer=dict(sha256=SETUP_SHA,bytes=SETUP_BYTES,signature_accepted=True,matches_pin=True),client_binaries=[dict(kind=k,sha256='b'*64,bytes=123,signature_accepted=True,file_version='2.1.0.1',version_status='accepted') for k in ('launcher','client')]);return r
 def test_native_version_windows_smoke(self):
  if sys.platform!='win32':self.skipTest('Requires native Windows version API')
  from native_version import query
  version,status=query(Path(sys.executable))
  self.assertEqual(status,'accepted');self.assertRegex(version,r'^[0-9]+(?:\.[0-9]+){3}$')
 def test_fixed_version(self):
  from native_version import fixed_version
  self.assertEqual(fixed_version((2<<16)|3,(4<<16)|5,0xfeef04bd),'2.3.4.5')
  for args in ((0,0,0xfeef04bd),(0,1,0),(True,1,0xfeef04bd),(-1,1,0xfeef04bd)):
   self.assertIsNone(fixed_version(*args))
 def test_bad_replica(self):
  r=self.report();r['replica']='r7'
  with self.assertRaises(ValueError):validate(r)
 def test_backward_time(self):
  r=self.success();r['ended_at']='2026-10-24T02:00:00Z'
  with self.assertRaises(ValueError):validate(r)
 def test_zero_version(self):
  r=self.success();r['client_binaries'][0]['file_version']='0.0.0.0'
  with self.assertRaises(ValueError):validate(r)
 def test_guard(self):
  e=self.env();self.assertTrue(authorized(e,'win32'))
  for k in e:
   if k in ('GITHUB_SHA','GITHUB_RUN_ID'):continue
   with self.subTest(key=k):
    x=e.copy();x[k]='wrong';self.assertFalse(authorized(x,'win32'))
  self.assertFalse(authorized(e,'linux'))
 def test_blank_valid(self):validate(self.report())
 def test_success(self):validate(self.success())
 def test_version_without_signature_is_not_evidence(self):
  r=self.success();r['client_binaries'][1]['signature_accepted']=False
  with self.assertRaises(ValueError):validate(r)
 def test_current_client_required(self):
  r=self.success();r['last_sample_process_names']=[]
  with self.assertRaises(ValueError):validate(r)
 def test_missing_numeric_version_cannot_pass(self):
  r=self.success();r['client_binaries'][1].update(file_version='',version_status='no_resource')
  with self.assertRaises(ValueError):validate(r)
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
 def test_layout_independent_of_registry_version(self):
  checks={k:True for k in CHECKS};checks['version_evidence_verified']=False
  self.assertTrue(layout_ready(checks));self.assertFalse(installed(checks,True))
  checks['signed_client']=False;self.assertFalse(layout_ready(checks))
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

class Batch(unittest.TestCase):
 env=Gates.env
 report=Gates.report
 success=Gates.success
 def test_missing_not_success(self):
  from publish_batch import summarize
  records,m=summarize({},'a'*40,'123');self.assertEqual(m['missing_replicas'],sorted(REPLICAS));self.assertFalse(m['all_six_target_windows_overlap']);self.assertEqual(sum(m['status_counts'].values()),0)
 def test_real_overlap_and_identity(self):
  from publish_batch import summarize
  inputs={}
  for k in sorted(REPLICAS):
   r=self.success(k);inputs[k]=json.dumps(r).encode()
  records,m=summarize(inputs,'a'*40,'123');self.assertEqual(len(records),6);self.assertEqual(m['common_overlap_seconds'],60);self.assertTrue(m['all_six_target_windows_overlap']);self.assertTrue(m['same_signed_client_hash_across_all_six'])
  r=self.success();r['replica']='r2';inputs['r1']=json.dumps(r).encode();records,m=summarize(inputs,'a'*40,'123');self.assertEqual(m['rejected_replicas'],['r1']);self.assertFalse(m['all_six_target_windows_overlap'])
 def test_nonoverlap(self):
  from publish_batch import summarize
  inputs={}
  for n,k in enumerate(sorted(REPLICAS)):
   r=self.success(k);r['started_at']=f'2026-10-25T02:{n*2:02d}:00Z';r['ended_at']=f'2026-10-25T02:{n*2+1:02d}:00Z';inputs[k]=json.dumps(r).encode()
  records,m=summarize(inputs,'a'*40,'123');self.assertEqual(m['common_overlap_seconds'],0);self.assertFalse(m['all_six_target_windows_overlap'])
 def test_malformed_report_not_raw_exported(self):
  from publish_batch import summarize
  records,m=summarize({'r1':b'{"secret":"must not publish"}'},'a'*40,'123');self.assertEqual(m['rejected_replicas'],['r1']);self.assertNotIn('secret',json.dumps(m))
