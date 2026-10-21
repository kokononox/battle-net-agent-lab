import json,os,sys,tempfile,time,unittest,subprocess
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from group import GroupSession,GROUP_ENDPOINTS
from core import validate,atomic,Session
import observer
class GroupTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.exe=self.root/'Wow.exe';self.exe.write_bytes(b'test');self.calls=[];self.present=set();self.fail_add=None;self.fail_remove=None;self.adds=0
  def fw(action,p):
   j=validate(json.loads(p.read_text()));self.calls.append((action,j['ip']))
   if action=='add':
    self.adds+=1;self.present.add(j['name'])
    if self.adds==self.fail_add:raise RuntimeError('add_failed')
   if action=='remove':
    if j['ip']==self.fail_remove:raise RuntimeError('remove_failed')
    self.present.discard(j['name'])
   return {'ok':True}
  self.fw=fw
  def collect(p):
   self.assertFalse(self.present,'monitor collection must follow ALL removals')
   return {'status':'sample_finished','scope':'any_group_target'}
  self.s=GroupSession(self.exe,self.root,fw,lambda p:p.with_suffix('.ready').write_text('ready'),lambda p:None,collect)
 def tearDown(self):self.tmp.cleanup()
 def test_fixed_group_is_exactly_recent_five(self):
  self.assertEqual(len(GROUP_ENDPOINTS),5);self.assertNotIn('37.244.29.11',[e['ip'] for e in GROUP_ENDPOINTS]);self.assertNotIn('37.244.62.60',[e['ip'] for e in GROUP_ENDPOINTS]);self.assertTrue(all(e['protocol']=='TCP' for e in GROUP_ENDPOINTS))
 def test_consent_required_before_any_side_effect(self):
  for consent in (False,None,1,'yes'):
   with self.assertRaises(RuntimeError):self.s.start_group(consent)
  self.assertEqual(self.calls,[]);self.assertEqual(list(self.s.private.glob('session-*.json')),[])
 def test_five_owned_rules_and_common_deadline(self):
  self.s.start_group(True);self.assertEqual(len(self.present),5);self.assertEqual(self.s.phase,'blocked');self.assertEqual(len({j['expires'] for p,j,i in self.s.members}),1)
 def test_all_journals_and_guards_before_first_add(self):
  def fw(action,p):
   if action=='add':
    self.assertEqual(len(list(self.s.private.glob('session-*.json'))),5)
    self.assertEqual(len(list(self.s.private.glob('session-*.ready'))),5)
   return self.fw(action,p)
  self.s.fw=fw;self.s.start_group(True)
 def test_second_start_refused(self):
  self.s.start_group(True)
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  with self.assertRaises(RuntimeError):self.s.start(0,True)
 def test_observation_is_group_not_individual(self):
  self.s.start_group(True);self.s.observe('world_ok',True);self.assertFalse(self.present);r=self.s.records[-1]
  self.assertEqual(r['mode'],'group');self.assertNotIn('endpoint',r);self.assertEqual(r['endpoints'],GROUP_ENDPOINTS);self.assertEqual(r['rule_absence_verified_count'],5);self.assertTrue(r['fresh_launch_user_reported']);self.assertFalse(r['packet_block_verified'])
 def test_reject_bad_observation_without_removing(self):
  self.s.start_group(True)
  with self.assertRaises(ValueError):self.s.observe('made_up')
  self.assertEqual(len(self.present),5)
 def test_baseline_gate_for_group(self):
  self.s.start_group(True);self.s.observe('world_ok');self.s.baseline('no')
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.s.baseline('yes');self.s.start_group(True);self.assertEqual(len(self.present),5)
 def test_probe_failure_no_add_cleanup_all(self):
  def fw(action,p):
   if action=='probe':raise RuntimeError('probe_failed')
   return self.fw(action,p)
  self.s.fw=fw
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertEqual(self.adds,0);self.assertEqual(sum(a=='remove' for a,ip in self.calls),5)
 def test_guard_failure_no_add(self):
  self.s.guard=lambda p:(_ for _ in ()).throw(RuntimeError('guard_failed'))
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertEqual(self.adds,0);self.assertFalse(self.present)
 def test_partial_add_failure_attempts_remove_every_member_preserves_uncertain_journals(self):
  self.fail_add=3
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertFalse(self.present);self.assertEqual(self.s.phase,'recovery_required');self.assertEqual(sum(a=='remove' for a,ip in self.calls),5);self.assertEqual(len(list(self.s.private.glob('session-*.json'))),5);self.assertEqual(self.s.records,[])
  # Independent watchdog ack allows uncertainty to be resolved; no success before it.
  p,j,i=self.s.members[2];p.with_suffix('.restored').write_text('absence_verified');self.s.restore();self.assertEqual(self.s.phase,'baseline')
 def test_one_removal_failure_does_not_skip_other_rules(self):
  self.s.start_group(True);self.fail_remove=GROUP_ENDPOINTS[1]['ip']
  with self.assertRaises(RuntimeError):self.s.restore()
  self.assertEqual(len(self.present),1);self.assertEqual(sum(a=='remove' for a,ip in self.calls),5);self.assertEqual(self.s.records,[]);self.assertEqual(len(list(self.s.private.glob('session-*.json'))),5)
  self.fail_remove=None;self.s.restore();self.assertFalse(self.present);self.assertTrue(self.s.records[-1]['rule_absence_verified'])
 def test_monitor_failure_rolls_back_all(self):
  self.s.monitor=lambda p:(_ for _ in ()).throw(RuntimeError('monitor_failed'))
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertFalse(self.present);self.assertEqual(self.s.records[-1]['reason'],'setup_failed')
 def test_monitor_collection_failure_does_not_hold_rules(self):
  self.s.start_group(True);self.s.monitor_stop=lambda p:(_ for _ in ()).throw(RuntimeError('monitor_failed'));self.s.restore();self.assertFalse(self.present);self.assertEqual(self.s.records[-1]['connection_monitor']['status'],'monitor_inconclusive')
 def test_expired_deadline_restores_all(self):
  self.s.start_group(True)
  for p,j,i in self.s.members:j['expires']=time.time()-1;atomic(p,j)
  self.s.status();self.assertFalse(self.present);self.assertEqual(self.s.phase,'baseline')
 def test_one_watchdog_ack_triggers_entire_group_cleanup(self):
  self.s.start_group(True);self.s.members[-1][0].with_suffix('.restored').write_text('absence_verified');self.s.status();self.assertFalse(self.present)
 def test_restart_recovery_all_members(self):
  self.s.start_group(True);Session(self.exe,self.root,self.fw).recover();self.assertFalse(self.present)
 def test_restart_recovery_continues_after_one_failure(self):
  self.s.start_group(True);self.fail_remove=GROUP_ENDPOINTS[0]['ip']
  with self.assertRaises(RuntimeError):Session(self.exe,self.root,self.fw).recover()
  self.assertEqual(len(self.present),1);self.assertEqual(sum(a=='remove' for a,ip in self.calls),5)
 def test_program_change_refused(self):
  self.exe.write_bytes(b'changed')
  with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertEqual(self.calls,[])
 def test_insufficient_setup_budget_prevents_adds(self):
  original=self.s.guard
  def guard(p):
   original(p)
   # Simulate slow setup without sleeping or modifying actual lease journals.
  self.s.guard=guard
  with patch('group.time.time',side_effect=[100,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320]):
   with self.assertRaises(RuntimeError):self.s.start_group(True)
  self.assertEqual(self.adds,0);self.assertFalse(self.present)
 def test_report_does_not_export_private_paths_or_owner_ids(self):
  self.s.start_group(True);self.s.observe('world_ok');raw=next(self.s.output.glob('*.json')).read_text();self.assertNotIn(str(self.exe),raw);self.assertNotIn('parent_pid',raw);self.assertNotIn('WoWEndpointStepsOwner',raw)
 def test_stop_marker_timestamp_is_preserved(self):
  p=self.root/'session-x.json';observer.signal_stop(p);first=p.with_suffix('.monitor-stop').read_text();time.sleep(.01);observer.signal_stop(p);self.assertEqual(first,p.with_suffix('.monitor-stop').read_text())

@unittest.skipUnless(os.environ.get('WOW_QA_PWSH'),'Real PowerShell runtime required')
class GroupRealMonitor(unittest.TestCase):
 def test_real_group_worker_tracks_non_primary_target_and_stops(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);i='d'*32;p=root/('session-'+i+'.json');exe=root/'Wow.exe'
   p.write_text(json.dumps({'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(exe),'parent_pid':os.getpid(),**GROUP_ENDPOINTS[0],'monitor_targets':GROUP_ENDPOINTS,'expires':time.time()+240}))
   # Actual PS worker/target matching/JSON handshake; Windows process/TCP/WFP APIs mocked.
   code="""function Get-Process { param($Id,$Name,$ErrorAction); [pscustomobject]@{Id=123;Path='%s';StartTime=[DateTime]::Now} }; function Get-NetTCPConnection { [pscustomobject]@{OwningProcess=123;RemoteAddress='37.244.62.205';RemotePort=3724;State='Established'} }; function Get-WinEvent { @() }; & ([scriptblock]::Create([IO.File]::ReadAllText('%s')))"""%(str(exe).replace("'","''"),str(Path(observer.__file__).parent/'monitor.ps1').replace("'","''"))
   # Stable process identity across repeated queries, born after worker start.
   code=code.replace("function Get-Process", "$script:born=[DateTime]::Now.AddSeconds(1); function Get-Process").replace('StartTime=[DateTime]::Now','StartTime=$script:born')
   env=os.environ.copy();env.update(WOW_STEPS_MONITOR_JOURNAL=str(p),DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1')
   proc=subprocess.Popen([os.environ['WOW_QA_PWSH'],'-NoLogo','-NoProfile','-NonInteractive','-Command',code],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    end=time.monotonic()+15
    while time.monotonic()<end and not p.with_suffix('.monitor-ready').exists():time.sleep(.05)
    self.assertTrue(p.with_suffix('.monitor-ready').exists());time.sleep(1.5)
    r=observer.stop(p);self.assertEqual(r['status'],'sample_finished');self.assertEqual(r['scope'],'any_group_target');self.assertIn('Established',r['target_tcp_states']);self.assertTrue(r['target_established_in_new_process_seen'])
    out,err=proc.communicate(timeout=10);self.assertEqual(proc.returncode,0,err.decode(errors='replace'))
   finally:
    if proc.poll() is None:proc.kill();proc.communicate()
if __name__=='__main__':unittest.main()
