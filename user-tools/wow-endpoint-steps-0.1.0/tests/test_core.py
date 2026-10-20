import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from core import Session,ENDPOINTS,OUTCOMES,validate,atomic

class WorkflowTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.program=self.root/'Wow.exe';self.program.write_bytes(b'fixture-not-an-executable');self.calls=[];self.present=set();self.failure=None
  def fw(action,path):
   j=validate(json.loads(Path(path).read_text()));self.calls.append(action)
   if self.failure==action:raise RuntimeError('mock_failure')
   if action=='add':self.present.add(j['name'])
   if action=='remove':self.present.discard(j['name'])
   return {'ok':True,'present':action=='add'}
  self.fw=fw;self.s=Session(self.program,self.root,fw,lambda p:p.with_suffix('.ready').write_text('ready'))
 def tearDown(self):self.t.cleanup()
 def test_twenty_seven_distinct_endpoints(self):self.assertEqual(len(ENDPOINTS),27);self.assertEqual(len({tuple(e.values()) for e in ENDPOINTS}),27)
 def test_protocol_split(self):self.assertEqual(sum(e['protocol']=='TCP' for e in ENDPOINTS),7)
 def test_consent_required(self):
  with self.assertRaises(RuntimeError):self.s.start(0,False)
  self.assertEqual(self.calls,[])
 def test_boolean_index_rejected(self):
  with self.assertRaises(ValueError):self.s.start(True,True)
 def test_bad_index_rejected(self):
  with self.assertRaises(ValueError):self.s.start(-1,True)
 def test_probe_precedes_add(self):self.s.start(0,True);self.assertEqual(self.calls,['probe','add'])
 def test_one_rule_only(self):
  self.s.start(0,True)
  with self.assertRaises(RuntimeError):self.s.start(1,True)
  self.assertEqual(len(self.present),1)
 def test_restore_before_baseline(self):
  self.s.start(0,True);self.s.observe('world_ok');self.assertFalse(self.present);self.assertEqual(self.s.phase,'baseline')
 def test_baseline_required_before_next(self):
  self.s.start(0,True);self.s.observe('world_ok')
  with self.assertRaises(RuntimeError):self.s.start(1,True)
  self.s.baseline('yes');self.s.start(1,True);self.assertEqual(len(self.present),1)
 def test_failed_baseline_stops(self):
  self.s.start(0,True);self.s.observe('auth_failed');self.s.baseline('no')
  with self.assertRaises(RuntimeError):self.s.start(1,True)
 def test_unknown_baseline_stops(self):
  self.s.start(0,True);self.s.restore();self.s.baseline('unknown');self.assertEqual(self.s.phase,'baseline')
 def test_invalid_observation_keeps_active(self):
  self.s.start(0,True)
  with self.assertRaises(ValueError):self.s.observe('invented')
  self.assertEqual(self.s.phase,'blocked')
 def test_observe_requires_active(self):
  with self.assertRaises(RuntimeError):self.s.observe('world_ok')
 def test_all_outcomes_restore(self):
  for outcome in OUTCOMES:
   self.s.start(0,True);self.s.observe(outcome);self.assertFalse(self.present);self.s.baseline('yes')
 def test_changed_exe_refuses(self):
  self.program.write_bytes(b'changed')
  with self.assertRaises(RuntimeError):self.s.start(0,True)
 def test_watchdog_failure_rolls_back(self):
  def fail(p):raise RuntimeError('guard_failed')
  self.s.guard=fail
  with self.assertRaises(RuntimeError):self.s.start(0,True)
  self.assertNotIn('add',self.calls);self.assertFalse(self.present)
 def test_watchdog_required(self):
  self.s.guard=None
  with self.assertRaises(RuntimeError):self.s.start(0,True)
  self.assertNotIn('add',self.calls)
 def test_add_failure_rolls_back(self):
  self.failure='add'
  with self.assertRaises(RuntimeError):self.s.start(0,True)
  self.assertEqual(self.calls,['probe','add','remove']);self.assertFalse(self.present)
 def test_probe_failure_no_add(self):
  self.failure='probe'
  with self.assertRaises(RuntimeError):self.s.start(0,True)
  self.assertNotIn('add',self.calls)
 def test_failed_removal_preserves_journal(self):
  self.s.start(0,True);self.failure='remove'
  with self.assertRaises(RuntimeError):self.s.restore()
  self.assertTrue(self.s.current[0].exists());self.assertTrue(self.present)
 def test_restart_recovery(self):
  self.s.start(0,True);other=Session(self.program,self.root,self.fw,lambda p:None);other.recover();self.assertFalse(self.present)
 def test_expired_lease_is_restored(self):
  self.s.start(0,True);p,j,i=self.s.current;j['expires']=time.time()-1;atomic(p,j);self.s.status();self.assertFalse(self.present);self.assertEqual(self.s.phase,'baseline')
 def test_watchdog_absence_recheck(self):
  self.s.start(0,True);p,j,i=self.s.current;self.fw('remove',p);p.with_suffix('.restored').write_text('absence_verified');j['expires']=time.time()-1;self.s.status();self.assertEqual(self.s.phase,'baseline')
 def test_no_private_path_in_report(self):
  self.s.start(0,True);self.s.observe('world_ok');s=next(self.s.output.glob('*.json')).read_text();self.assertNotIn(str(self.program),s);self.assertNotIn('parent_pid',s);self.assertNotIn('group',s)
 def test_invalid_ownership_no_removal(self):
  self.s.start(0,True);p,j,i=self.s.current;j['group']='other';atomic(p,j);self.calls.clear()
  with self.assertRaises(ValueError):self.s.recover()
  self.assertEqual(self.calls,[])
 def test_unknown_destination_refused(self):
  self.s.start(0,True);p,j,i=self.s.current;j['ip']='1.1.1.1'
  with self.assertRaises(ValueError):validate(j)
 def test_invalid_name_refused(self):
  self.s.start(0,True);p,j,i=self.s.current;j['name']='unrelated'
  with self.assertRaises(ValueError):validate(j)
 def test_reports_no_packet_claim(self):
  self.s.start(0,True);self.s.restore();self.assertFalse(self.s.records[0]['packet_block_verified'])

class SourceGuards(unittest.TestCase):
 def test_no_policy_bypass(self):
  s=(Path(__file__).resolve().parents[1]/'app/core.py').read_text();self.assertNotIn('-ExecutionPolicy',s)
 def test_only_loopback_listener(self):
  s=(Path(__file__).resolve().parents[1]/'app/main.py').read_text();self.assertIn("(('127.0.0.1',0)",s);self.assertIn('compare_digest',s);self.assertIn("self.headers.get('Host')==self.server.authority",s)
 def test_no_disable_firewall_or_global_delete(self):
  s=(Path(__file__).resolve().parents[1]/'app/firewall.ps1').read_text();self.assertNotIn('Set-NetFirewallProfile',s);self.assertIn('Ownership mismatch',s);self.assertIn('RemotePort $j.port',s);self.assertIn('-Program $j.program',s)
 def test_native_claim_not_in_code(self):
  s=(Path(__file__).resolve().parents[1]/'app/core.py').read_text();self.assertIn("'packet_block_verified':False",s)
if __name__=='__main__':unittest.main()
