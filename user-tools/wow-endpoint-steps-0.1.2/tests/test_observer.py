import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from observer import clean,stop
from core import Session
class ObserverTests(unittest.TestCase):
 def test_public_only(self):
  rows=[{'ip':ip,'port':443,'state':'Established','samples':1,'new_process_seen':True} for ip in ('127.0.0.1','10.1.2.3','192.168.1.1','3.124.215.108')]
  x=clean({'status':'sample_finished','tcp_endpoints':rows});self.assertEqual(len(x['public_tcp_endpoints']),1)
 def test_no_evidence_not_block_proof(self):
  x=clean({'status':'sample_finished'});self.assertEqual(x['finding'],'no_target_evidence_in_sample');self.assertFalse(x['rule_causality_proven'])
 def test_wfp_positive_not_rule_attribution(self):
  x=clean({'matching_wfp_block_events':2});self.assertEqual(x['finding'],'matching_windows_block_decision_observed');self.assertFalse(x['rule_causality_proven'])
 def test_new_process_established(self):
  x=clean({'target_established_in_new_process_seen':True});self.assertEqual(x['finding'],'target_established_in_new_process_observed')
 def test_existing_socket_unknown_freshness(self):self.assertEqual(clean({'target_tcp_states':['Established']})['finding'],'target_socket_observed_freshness_unproven')
 def test_private_fields_omitted(self):
  x=clean({'program':'C:\\Secret\\Wow.exe','pid':123,'raw_event':'secret','status':'sample_finished'});self.assertNotIn('Secret',json.dumps(x));self.assertNotIn('raw_event',x)
 def test_invalid_ip_omitted(self):self.assertEqual(clean({'tcp_endpoints':[{'ip':'bad','port':1,'state':'Established'}]})['public_tcp_endpoints'],[])
 def test_stop_before_remove(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);p=r/'Wow.exe';p.write_bytes(b'fixture');calls=[]
   def fw(a,j):calls.append(a);return {'ok':True}
   def mon(j):calls.append('monitor_start')
   def end(j):calls.append('monitor_stop');return {'status':'sample_finished'}
   s=Session(p,r,fw,lambda p:None,mon,end);s.start(0,True);s.observe('world_ok',True)
   self.assertLess(calls.index('monitor_stop'),calls.index('remove'));self.assertTrue(s.records[0]['fresh_launch_user_reported']);self.assertIn('connection_monitor',s.records[0])
 def test_monitor_setup_failure_restores(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);p=r/'Wow.exe';p.write_bytes(b'fixture');calls=[]
   def mon(j):raise RuntimeError('monitor_failed')
   s=Session(p,r,lambda a,j:calls.append(a),lambda p:None,mon,lambda p:{'status':'not_started'})
   with self.assertRaises(RuntimeError):s.start(0,True)
   self.assertIn('remove',calls)
 def test_no_new_test_of_failed_login_target(self):
  with tempfile.TemporaryDirectory() as t:
   from core import ENDPOINTS
   r=Path(t);p=r/'Wow.exe';p.write_bytes(b'fixture');s=Session(p,r,lambda a,j:None,lambda p:None)
   idx=next(i for i,e in enumerate(ENDPOINTS) if e['ip']=='37.244.29.11')
   with self.assertRaisesRegex(RuntimeError,'not_in_six_endpoint_review'):s.start(idx,True)
 def test_no_audit_enabling_or_payload_capture(self):
  s=(Path(__file__).resolve().parents[1]/'app/monitor.ps1').read_text()
  for bad in ['Set-Net','auditpol.exe','/set','New-Net','netsh','pktmon']:self.assertNotIn(bad,s)
  self.assertIn("Get-WinEvent -FilterHashtable",s);self.assertIn('Get-NetTCPConnection',s)
 def test_stop_returns_existing_sanitized_result(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'session-test.json';p.with_suffix('.monitor-result').write_text('{"status":"sample_finished","raw_event":"secret"}')
   self.assertNotIn('raw_event',stop(p));self.assertTrue(p.with_suffix('.monitor-stop').exists())
if __name__=='__main__':unittest.main()
