import copy,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from calibrated_hosts import *
def view(kind='public'):
 p=result('dns_error',11004) if kind=='no_data' else result('answers',counts=classify(['8.8.8.8' if kind=='public' else '0.0.0.0' if kind=='unspecified' else '127.0.0.1']))
 return {k:copy.deepcopy(p) for k in FAMILIES}
class CalibratedTests(unittest.TestCase):
 def setup_case(self,d,mode='no_data',control='public'):
  path=Path(d)/'hosts';path.write_bytes(b'# original\r\n');r=blank(DOMAINS[0])
  def observe(domain,env):return view(control if domain==CONTROL else mode if b'BEGIN' in path.read_bytes() else 'public')
  return path,r,CalibratedHosts(path,d,r,{},observe,lambda e:0,lambda p:True)
 def test_no_data_with_calibration_accepted_and_restored(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.apply();self.assertTrue(x.check());self.assertEqual(r['checks'][0]['resolver_state'],'accepted_no_data');self.assertTrue(x.restore());self.assertEqual(path.read_bytes(),b'# original\r\n');validate_record(r)
 def test_zero_addresses_still_accepted(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d,'unspecified');x.apply();self.assertTrue(x.restore());validate_record(r)
 def test_no_data_baseline_refused_before_write(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.observe=lambda domain,env:view('no_data')
   with self.assertRaisesRegex(ValueError,'baseline_not_healthy'):x.apply()
   self.assertFalse(x.touched);self.assertEqual(path.read_bytes(),b'# original\r\n');self.assertFalse(r['backup_created']);validate_record(r)
 def test_control_failure_during_override_refused(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);original=x.observe
   x.observe=lambda domain,env:view('no_data') if domain==CONTROL and b'BEGIN' in path.read_bytes() else original(domain,env)
   with self.assertRaisesRegex(ValueError,'override_not_verified'):x.apply()
   self.assertTrue(x.restore());self.assertEqual(r['verification_failures'],1);validate_record(r)
 def test_other_errors_and_public_and_loopback_refused(self):
  for p in [result('dns_error',11001),result('dns_error',11002),result('timeout'),result('helper_nonzero',1),result('output_rejected'),result('os_error',5),result('answers',counts=classify(['0.0.0.0','8.8.8.8']))]:
   with self.subTest(probe=p):self.assertEqual(blocked_state({k:p for k in FAMILIES}),'refused')
  for kind in ['public','loopback']:
   with tempfile.TemporaryDirectory() as d:
    path,r,x=self.setup_case(d,kind)
    with self.assertRaisesRegex(ValueError,'override_not_verified'):x.apply()
    self.assertTrue(x.restore());validate_record(r)
 def test_overwritten_hosts_not_restored_over_other_change(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.apply();path.write_bytes(b'# unrelated');self.assertFalse(x.check());self.assertFalse(x.restore());self.assertEqual(path.read_bytes(),b'# unrelated');validate_record(r)
 def test_restore_dns_failure_not_restored(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.apply();original=x.observe
   x.observe=lambda domain,env:view('no_data') if domain==r['domain'] else original(domain,env)
   self.assertFalse(x.restore());self.assertTrue(r['file_restored']);self.assertFalse(r['restored']);validate_record(r)
 def test_flush_failure_no_success(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.flush_fn=lambda e:1
   with self.assertRaisesRegex(ValueError,'flush_failed'):x.apply()
   self.assertFalse(x.restore());self.assertTrue(r['file_restored']);validate_record(r)
 def test_record_cannot_claim_false_acceptance(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.apply();x.restore();r['checks'][0]['observations']['control']=view('no_data')
   with self.assertRaises(ValueError):validate_record(r)
 def test_numeric_child_protocol(self):
  env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','TEMP','TMP'}}
  p=probe('0.0.0.0','any',env);self.assertTrue(only(p,'unspecified'))
 def test_unknown_domain_no_subprocess(self):
  run=Mock()
  with self.assertRaises(ValueError):probe('unknown.invalid','any',{},run)
  run.assert_not_called()
 def test_unsafe_path_refused(self):
  with tempfile.TemporaryDirectory() as d:
   path,r,x=self.setup_case(d);x.safe=lambda p:False
   with self.assertRaisesRegex(ValueError,'path_refused'):x.apply()
   self.assertEqual(path.read_bytes(),b'# original\r\n');self.assertFalse(x.touched)

class QualificationTests(unittest.TestCase):
 def env(self):
  import qualify_calibrated_hosts as q
  return dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/'+q.BRANCH,GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_DNS_D2=q.APPROVAL,BNET_DNS_CASE='telemetry',GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
 def test_qualification_guard(self):
  import qualify_calibrated_hosts as q
  env=self.env();self.assertTrue(q.authorized(env,'win32'))
  for k in env:
   bad=env.copy();bad[k]='bad';self.assertFalse(q.authorized(bad,'win32'),k)
  self.assertFalse(q.authorized(env,'linux'))
 def test_qualification_refused_before_writes(self):
  from unittest.mock import patch
  import qualify_calibrated_hosts as q
  with patch.dict(os.environ,{},clear=True),patch('pathlib.Path.write_text') as write,self.assertRaises(SystemExit):q.main()
  write.assert_not_called()
 def test_qualified_claim_requires_three_checks_and_restore(self):
  import qualify_calibrated_hosts as q
  with tempfile.TemporaryDirectory() as d:
   path,r,x=CalibratedTests().setup_case(d);x.apply();x.check();x.check();x.restore()
   report=dict(schema='bnet-calibrated-hosts-d2-1',source_commit='a'*40,run_id='123',case='telemetry',status='qualified',installer_launched=False,all_traffic_blocked_proven=False,error_code=None,hosts=r)
   q.validate(report)
   for field,value in [('restored',False),('verification_failures',1)]:
    bad=copy.deepcopy(report);bad['hosts'][field]=value
    with self.assertRaises(ValueError):q.validate(bad)
   for field in ['installer_launched','all_traffic_blocked_proven']:
    bad=copy.deepcopy(report);bad[field]=True
    with self.assertRaises(ValueError):q.validate(bad)

class AdapterTests(unittest.TestCase):
 def test_summary_crossfoot_including_failure(self):
  from hosts_experiment import CalibratedAdapter
  from experiment_policy import hosts_blank
  with tempfile.TemporaryDirectory() as d:
   path,c,x=CalibratedTests().setup_case(d);r=hosts_blank('r3');r['calibration']=c;adapter=CalibratedAdapter(x,r)
   adapter.apply();self.assertTrue(r['resolver_verified']);self.assertEqual(r['verification_checks'],1)
   path.write_bytes(b'# conflict');self.assertFalse(adapter.check());self.assertFalse(r['resolver_verified']);self.assertEqual(r['verification_failures'],1);self.assertFalse(adapter.restore())
 def test_new_install_requires_calibration(self):
  from test_model import Gates
  from model import validate
  r=Gates().success('r3');r['hosts']['calibration']=None
  with self.assertRaisesRegex(ValueError,'calibration_required'):validate(r)
 def test_false_calibration_summary_rejected(self):
  from test_model import Gates
  from model import validate
  r=Gates().success('r3');r['hosts']['calibration']['checks'][0]['accepted']=False
  with self.assertRaises(ValueError):validate(r)
 def test_control_factory_is_noop(self):
  from hosts_experiment import for_runner
  from test_model import Gates
  from experiment_policy import hosts_blank
  from unittest.mock import patch
  from types import SimpleNamespace
  with patch.dict(os.environ,dict(Gates().env(),SystemRoot='X:/unused'),clear=True),patch('hosts_experiment.sys.platform','win32'):
   r=hosts_blank('r1');x=for_runner('/unused',r,{},SimpleNamespace(is_reparse=Mock(side_effect=AssertionError('control touched disk'))));x.apply();self.assertTrue(x.check());self.assertTrue(x.restore());self.assertIsNone(r['calibration'])
