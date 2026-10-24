import copy,datetime,pathlib,sys,tempfile,unittest,zipfile,json
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tests')]
import baseline_ops as bo,monitor_evidence as me
from policy import PolicyError
from state import Store

def capture():
 t='2026-10-24T12:00:00Z';cut=me.utc_ticks(me.instant('2026-10-24T11:59:00Z'));birth=str(cut+10000000);pid='a'*24
 p=dict(id=pid,path=r'C:\Apps\Game.exe',registered_for_firewall=False,hash_verified=False)
 process=dict(record_id='b'*32,program_id=pid,program_path=p['path'],pid=100,process_start_ticks=birth,first_seen_utc=t,last_seen_utc=t,presence='present',registered_for_firewall=False,hash_verified=False)
 row=dict(record_id='c'*32,program_id=pid,program_path=p['path'],pid=100,process_start_ticks=birth,protocol='TCP',local_ip='10.0.0.1',local_port=50000,remote_ip='8.8.8.8',remote_port=443,first_seen_utc=t,last_seen_utc=t,samples=1,states={'Established':1},presence='present')
 return dict(schema='unified-new-process-monitor-1',observation_mode='new_processes',capture_id='d'*32,status='finished',baseline_ready=True,baseline_cutoff_ticks=str(cut),baseline_utc='2026-10-24T11:59:00Z',baseline_existing_count=10,baseline_unreadable_count=1,programs=[p],processes=[process],endpoints=[row],revision=3,ready=True,last_sample_ok=True,truncated=False,successful_samples=1,query_errors=0,publication_errors=0,unreadable_process_instances=0,started_utc=t,published_utc=t,ended_utc=t,firewall_changed=False,hosts_changed=False,packet_drop_verified=False)
class BaselineTests(unittest.TestCase):
 def setUp(self):self.c=capture()
 def test_stop_does_not_depend_on_hidden_program_button(self):
  s=(ROOT/'app/ui.ps1').read_text(encoding='utf-8-sig');self.assertNotIn('$stop.PerformClick()',s);self.assertIn('$popupStop.Add_Click({TryOp {Request-MonitorStop}})',s);self.assertIn('$monitorStop.Enabled=$stop.Enabled',s)
 def test_baseline_live_frame_has_program_process_caps(self):
  s=(ROOT/'app/ui.ps1').read_text(encoding='utf-8-sig');self.assertIn('invalid_baseline_live_limits',s);self.assertIn('@($value.processes).Count -gt 2000',s)
 def test_new_mode_does_not_need_saved_exe_hash(self):self.assertFalse(bo.validate(self.c)['programs'][0]['hash_verified'])
 def test_empty_discovery_is_valid(self):
  self.c.update(programs=[],processes=[],endpoints=[]);self.assertEqual(bo.validate(self.c)['processes'],[])
 def test_new_instance_DNS_kept_without_registration(self):
  p=self.c['processes'][0];self.c['event_evidence']=dict(events=[dict(record_id='e'*32,program_id=p['program_id'],program_path=p['program_path'],pid=p['pid'],process_start_ticks=p['process_start_ticks'],event_record_id=1,observed_utc=p['last_seen_utc'],kind='dns_query',source='DNSClient_ETW',dns_event_id=3008,domain='query.example',dns_status='0',query_results='8.8.8.8;')]);c=bo.validate(self.c);self.assertEqual(len(c['event_evidence']['events']),1);self.assertEqual(c['endpoints'][0]['dns_names'],['query.example'])
 def test_old_instance_DNS_not_attributed_to_new_PID(self):
  p=self.c['processes'][0];self.c['event_evidence']=dict(events=[dict(record_id='e'*32,program_id=p['program_id'],program_path=p['program_path'],pid=p['pid'],process_start_ticks=str(int(self.c['baseline_cutoff_ticks'])-1),event_record_id=1,observed_utc=p['last_seen_utc'],kind='dns_query',source='DNSClient_ETW',dns_event_id=3008,domain='old.example',dns_status='0',query_results='8.8.8.8;')]);c=bo.validate(self.c);self.assertFalse(c['event_evidence']['events']);self.assertFalse(c['endpoints'][0]['dns_names']);self.assertTrue(c['event_evidence']['truncated'])
 def test_baseline_cutoff_must_match_UTC_label(self):
  self.c['baseline_cutoff_ticks']='1'
  with self.assertRaisesRegex(PolicyError,'cutoff_time'):bo.validate(self.c)
 def test_start_does_not_verify_or_modify_saved_selection(self):
  s=(ROOT/'app/baseline_ops.py').read_text();self.assertNotIn('verified_programs',s);self.assertIn('state=store.read()',s)
 def test_old_birth_rejected(self):
  self.c['processes'][0]['process_start_ticks']=self.c['baseline_cutoff_ticks']
  with self.assertRaisesRegex(PolicyError,'birth'):bo.validate(self.c)
 def test_PID_without_birth_not_enough(self):
  self.c['processes'][0].pop('process_start_ticks')
  with self.assertRaises(PolicyError):bo.validate(self.c)
 def test_same_PID_different_birth_separate(self):
  p=copy.deepcopy(self.c['processes'][0]);p.update(record_id='e'*32,process_start_ticks=str(int(p['process_start_ticks'])+1));self.c['processes'].append(p);self.assertEqual(len(bo.validate(self.c)['processes']),2)
 def test_duplicate_instance_rejected(self):
  p=copy.deepcopy(self.c['processes'][0]);p['record_id']='e'*32;self.c['processes'].append(p)
  with self.assertRaises(PolicyError):bo.validate(self.c)
 def test_process_path_must_match_program(self):
  self.c['processes'][0]['program_path']=r'C:\Other\Game.exe'
  with self.assertRaises(PolicyError):bo.validate(self.c)
 def test_endpoint_must_belong_to_new_instance(self):
  self.c['endpoints'][0]['pid']=200
  with self.assertRaises(PolicyError):bo.validate(self.c)
 def test_native_registration_claim_rejected(self):
  self.c['programs'][0]['registered_for_firewall']=True
  with self.assertRaises(PolicyError):bo.validate(self.c)
 def test_forged_block_state_not_trusted(self):
  self.c['endpoints'][0]['rule_state']='verified_owned_block_snapshot';self.assertEqual(bo.validate(self.c)['endpoints'][0]['rule_state'],'unknown')
 def test_process_cap(self):
  self.c['processes']=[self.c['processes'][0]]*2001
  with self.assertRaisesRegex(PolicyError,'limits'):bo.validate(self.c)
 def test_program_cap(self):
  self.c['programs']=[self.c['programs'][0]]*513
  with self.assertRaisesRegex(PolicyError,'limits'):bo.validate(self.c)
 def test_naive_time_rejected(self):
  self.c['baseline_utc']='2026-10-24T11:59:00'
  with self.assertRaises(ValueError):bo.validate(self.c)
 def test_unknown_process_state_is_not_exit(self):
  self.c['processes'][0]['presence']='not_in_latest_snapshot';self.assertEqual(bo.validate(self.c)['processes'][0]['presence'],'not_in_latest_snapshot')
 def test_network_mutation_flag_rejected(self):
  self.c['firewall_changed']=True
  with self.assertRaisesRegex(PolicyError,'scope'):bo.validate(self.c)
 def test_archive_is_separate_from_fixed_EXE_captures(self):
  with tempfile.TemporaryDirectory() as temp:
   a=bo.Archive(pathlib.Path(temp));p=a.save(self.c);self.assertIn('baseline-captures',str(p));self.assertEqual(a.load(self.c['capture_id'])['schema'],self.c['schema'])
 def test_archive_does_not_overwrite(self):
  with tempfile.TemporaryDirectory() as temp:
   a=bo.Archive(pathlib.Path(temp));a.save(self.c)
   with self.assertRaisesRegex(PolicyError,'exists'):a.save(self.c)
 def test_export_strips_all_exe_paths(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp)/'private';store=Store(root);bo.Archive(root).save(self.c);job=pathlib.Path(temp)/'job';job.mkdir();result=bo.export(store,dict(capture_id=self.c['capture_id']),job)
   with zipfile.ZipFile(result['export_file']) as z:
    clean=json.loads(z.read('capture.json'));self.assertNotIn('path',clean['programs'][0]);self.assertNotIn('program_path',clean['processes'][0]);self.assertNotIn('program_path',clean['endpoints'][0])
 def test_no_automatic_apply_or_registration_in_backend(self):
  s=(ROOT/'app/baseline_ops.py').read_text()
  for bad in ('store.register','store.add_blacklist','native_apply','verified_programs(','store.configure('):self.assertNotIn(bad,s)
 def test_no_suspend_or_kill_in_collector(self):
  s=(ROOT/'app/baseline.ps1').read_text('utf-8-sig')
  for bad in ('Stop-Process','Suspend-Process','taskkill','Set-NetFirewall','UCreateNative','Start-Process'):self.assertNotIn(bad,s)
 def test_layout_is_explicit_right_menu_and_percent_workspace(self):
  s=(ROOT/'app/ui-layout.ps1').read_text('utf-8-sig');self.assertIn("$workspace.RightToLeft='No'",s);self.assertIn('$workspace.Controls.Add($sidebarHost,1,0)',s);self.assertIn('$workspace.Controls.Add($tabs,0,0)',s);self.assertIn("$menu.FlowDirection='TopDown'",s);self.assertIn("$menu.AutoScroll=$true",s);self.assertIn('Maximize-TableRow $m 2',s);self.assertIn('$historyPanel.Controls.Add($historyGrid,0,0)',s)
 def test_native_controls_and_recovery_callbacks_reused(self):
  s=(ROOT/'app/ui-layout.ps1').read_text('utf-8-sig');self.assertIn('Add-ToolControl $blackTools $apply',s);self.assertIn('Add-ToolControl $recoveryTools $restore',s);self.assertNotIn("BeginOp 'native_",s)
 def test_baseline_start_needs_no_CheckedIds(self):
  s=(ROOT/'app/ui-baseline.ps1').read_text('utf-8-sig');self.assertNotIn('CheckedIds',s);self.assertIn("BeginOp 'baseline_record'",s)
 def test_baseline_can_stop_and_close_normally(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertGreaterEqual(s.count("@('monitor_record','baseline_record')"),5);self.assertIn("Prefill-Observed $liveGrid 'endpoint' 'blacklist'",s)
if __name__=='__main__':unittest.main()
