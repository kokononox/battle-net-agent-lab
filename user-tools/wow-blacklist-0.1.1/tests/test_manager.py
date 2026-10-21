import json,sys,tempfile,unittest,ipaddress
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import Manager,BlacklistError,parse_list,format_list,spec,atomic,BASE
class ParseTests(unittest.TestCase):
 def test_tcp_udp_ipv6_and_comments(self):
  r=parse_list('3.125.189.135:443 tcp # note\n[2606:4700:4700::1111]:53 UDP');self.assertEqual(len(r),2);self.assertEqual(r[0]['protocol'],'TCP');self.assertEqual(parse_list(format_list(r)),r)
 def test_private_loopback_multicast_reserved_refused(self):
  for ip in ('10.0.0.1','127.0.0.1','192.168.0.1','169.254.1.1','224.0.0.1','0.0.0.0','255.255.255.255','[::1]','[fc00::1]'):
   with self.subTest(ip=ip),self.assertRaises(BlacklistError):parse_list(ip+':443 TCP')
 def test_no_domains_ranges_wildcards_or_shell(self):
  for line in ('example.com:443 TCP','1.1.1.1:* TCP','1.1.1.0/24:443 TCP','1.1.1.1:443-445 TCP','1.1.1.1:443 TCP; calc','1.1.1.1:443 ALL','1.1.1.1:0 TCP','1.1.1.1:65536 TCP'):
   with self.subTest(line=line),self.assertRaises(BlacklistError):parse_list(line)
 def test_duplicates_normalized(self):self.assertEqual(len(parse_list('1.1.1.1:443 tcp\n1.1.1.1:443 TCP')),1)
 def test_max_entries(self):
  with self.assertRaises(BlacklistError):parse_list('\n'.join('1.1.1.1:'+str(p)+' TCP' for p in range(1,102)))
 def test_invalid_input_types(self):
  for text in (None,[],{},'x'*30001):
   with self.assertRaises(BlacklistError):parse_list(text)
 def test_spec_identity_stable_scoped_and_port_exact(self):
  e=parse_list('1.1.1.1:443 TCP')[0];a=spec('a'*32,'C:/Game/Wow.exe',e);self.assertEqual(a,spec('a'*32,'c:/game/wow.exe',e));self.assertNotEqual(a['name'],spec('b'*32,'C:/Game/Wow.exe',e)['name']);self.assertNotEqual(a['name'],spec('a'*32,'C:/Game/Wow.exe',{**e,'port':80})['name'])
class ManagerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/'app').mkdir();(self.root/'app/defaults.json').write_bytes((BASE/'app/defaults.json').read_bytes());self.exe=self.root/'Wow.exe';self.exe.write_bytes(b'fixture');self.calls=[];self.actual={};self.fail=False
  def fw(plan,job):
   self.calls.append(plan)
   if self.fail:raise BlacklistError('fake_failure')
   if plan['action']=='apply':self.actual={e['name']:e for e in plan['entries']};return dict(config_verified=True,persistent_count=len(self.actual),active_count=len(self.actual))
   if plan['action']=='restore':self.actual={};return dict(absence_verified=True,persistent_count=0,active_count=0)
   return dict(persistent_count=len(self.actual),active_count=len(self.actual))
  self.m=Manager(self.root,fw=fw);self.m.run('load');self.calls.clear()
  self.payload=dict(program=str(self.exe),text='1.1.1.1:443 TCP\n8.8.8.8:53 UDP',persistent_consent=True)
 def tearDown(self):self.tmp.cleanup()
 def test_initial_ten_defaults_do_not_apply(self):self.assertEqual(len(parse_list(self.m.config()['text'])),10);self.assertEqual(self.actual,{})
 def test_owner_has_consistent_backup(self):self.assertEqual(self.m.owner(),json.loads((self.m.private/'owner-id.backup.json').read_text())['owner'])
 def test_corrupt_primary_owner_recovers_from_backup(self):
  owner=self.m.owner();(self.m.private/'owner-id.json').write_text('invalid');self.assertEqual(self.m.owner(),owner)
 def test_owner_disagreement_refuses(self):
  atomic(self.m.private/'owner-id.backup.json',{'owner':'f'*32})
  with self.assertRaises(BlacklistError):self.m.owner()
 def test_missing_owner_does_not_invent_identity_for_restore(self):
  for p in self.m.private.glob('owner-id*'):p.unlink()
  with self.assertRaises(BlacklistError):self.m.run('restore')
 def test_apply_requires_exact_true_consent(self):
  for x in (False,1,'yes',None):
   with self.assertRaises(BlacklistError):self.m.run('apply',{**self.payload,'persistent_consent':x})
  self.assertEqual(self.calls,[])
 def test_apply_records_pending_before_mutation(self):
  fw=self.m.fw
  def inspect(plan,job):self.assertEqual(self.m.config()['phase'],'applying');return fw(plan,job)
  self.m.fw=inspect;self.m.run('apply',self.payload);self.assertEqual(self.m.config()['phase'],'applied')
 def test_apply_persists_after_new_manager_instance(self):
  self.m.run('apply',self.payload);other=Manager(self.root,fw=self.m.fw);self.assertEqual(other.config()['phase'],'applied');self.assertEqual(len(self.actual),2)
 def test_edit_update_removes_only_omitted_owned_target(self):
  self.m.run('apply',self.payload);old=set(self.actual);self.m.run('apply',{**self.payload,'text':'1.1.1.1:443 TCP'});self.assertEqual(len(self.actual),1);self.assertTrue(set(self.actual)<old)
 def test_save_only_never_changes_firewall(self):
  self.m.run('save',self.payload);self.assertEqual(self.calls,[]);self.assertEqual(self.actual,{})
 def test_observe_never_changes_firewall_and_filters_private(self):
  self.m.collector=lambda plan,job:dict(endpoints=[dict(ip='1.1.1.1',port=443,samples=2,fresh_process_seen=True,pid=99),dict(ip='10.0.0.1',port=80),dict(ip='224.0.0.1',port=80)],seconds=1,query_errors=0)
  result=self.m.run('observe',dict(program=str(self.exe),seconds=60));self.assertEqual(self.calls,[]);rows=result['observation']['endpoints'];self.assertEqual(len(rows),1);self.assertNotIn('pid',rows[0]);self.assertFalse(result['observation']['firewall_changed_by_observe'])
 def test_observe_invalid_duration_refused(self):
  with self.assertRaises(BlacklistError):self.m.run('observe',dict(program=str(self.exe),seconds=1000))
 def test_failure_preserves_needs_restore_and_blocks_reapply(self):
  self.fail=True
  with self.assertRaises(BlacklistError):self.m.run('apply',self.payload)
  self.assertEqual(self.m.config()['phase'],'needs_restore');self.fail=False
  with self.assertRaises(BlacklistError):self.m.run('apply',self.payload)
  self.m.run('restore');self.m.run('apply',self.payload);self.assertEqual(self.m.config()['phase'],'applied')
 def test_bad_readback_is_not_success(self):
  self.m.fw=lambda p,j:dict(config_verified=True,persistent_count=1,active_count=1)
  with self.assertRaises(BlacklistError):self.m.run('apply',self.payload)
  self.assertEqual(self.m.config()['phase'],'needs_restore')
 def test_restore_retains_desired_list(self):
  self.m.run('apply',self.payload);before=self.m.config()['text'];self.m.run('restore');self.assertFalse(self.actual);self.assertEqual(self.m.config()['text'],before);self.assertEqual(self.m.config()['phase'],'restored')
 def test_restore_works_with_corrupt_settings(self):
  self.m.run('apply',self.payload);self.m.config_path.write_text('corrupt');self.m.run('restore');self.assertFalse(self.actual)
 def test_restore_needs_absence_verification(self):
  self.m.fw=lambda p,j:{}
  with self.assertRaises(BlacklistError):self.m.run('restore')
 def test_known_login_target_needs_extra_confirmation(self):
  p={**self.payload,'text':'37.244.29.11:3724 TCP'}
  with self.assertRaises(BlacklistError):self.m.run('apply',p)
  self.m.run('apply',{**p,'critical_consent':True});self.assertEqual(len(self.actual),1)
 def test_empty_apply_refused_use_restore(self):
  with self.assertRaises(BlacklistError):self.m.run('apply',{**self.payload,'text':''})
 def test_wrong_exe_refused(self):
  with self.assertRaises(BlacklistError):self.m.run('apply',{**self.payload,'program':str(self.root/'other.exe')})
 def test_changed_exe_needs_reselection(self):
  self.m.run('apply',self.payload);self.exe.write_bytes(b'new version')
  with self.assertRaises(BlacklistError):self.m.run('apply',self.payload)
  self.m.run('apply',{**self.payload,'program_reselected':True})
 def test_reports_exclude_owner_and_private_path(self):
  self.m.run('apply',self.payload);raw=next(self.m.output.glob('blacklist-result-*.json')).read_text();self.assertNotIn(str(self.exe),raw);self.assertNotIn(self.m.owner(),raw);self.assertIn('"packet_block_verified": false',raw)
 def test_invalid_list_has_no_firewall_side_effect(self):
  with self.assertRaises(BlacklistError):self.m.run('apply',{**self.payload,'text':'*:* TCP'})
  self.assertEqual(self.calls,[])
 def test_status_does_not_save_or_mutate_rules(self):
  self.m.run('apply',self.payload);before=self.m.config_path.read_bytes();old=dict(self.actual);self.calls.clear()
  result=self.m.run('status',{**self.payload,'text':'1.1.1.1:443 TCP'})
  self.assertEqual(self.m.config_path.read_bytes(),before);self.assertEqual(self.actual,old);self.assertEqual([c['action'] for c in self.calls],['status']);self.assertEqual(len(self.calls[0]['entries']),1);self.assertNotIn('config',result)
 def test_load_requests_exact_entry_readback(self):
  self.m.run('apply',self.payload);self.calls.clear();self.m.run('load');self.assertEqual(self.calls[0]['program'],str(self.exe));self.assertEqual(len(self.calls[0]['entries']),2)
 def test_explicit_empty_apply_restores_and_stores_empty_list(self):
  self.m.run('apply',self.payload);self.m.run('apply',{**self.payload,'text':'','empty_restore_consent':True});self.assertEqual(self.actual,{});self.assertEqual(self.m.config()['text'],'');self.assertEqual(self.m.config()['phase'],'restored');self.assertEqual(self.calls[-1]['action'],'restore')
 def test_empty_apply_requires_verified_restore(self):
  self.m.fw=lambda p,j:dict(absence_verified=False)
  with self.assertRaises(BlacklistError):self.m.run('apply',{**self.payload,'text':'','empty_restore_consent':True})
  self.assertEqual(self.m.config()['phase'],'needs_restore')
 def test_repeated_single_removal_keeps_other_rules(self):
  self.m.run('apply',self.payload);remaining=self.payload['text'].splitlines()[1];self.m.run('apply',{**self.payload,'text':remaining});self.assertEqual(len(self.actual),1);self.assertEqual(next(iter(self.actual.values()))['ip'],'8.8.8.8')
  self.m.run('apply',{**self.payload,'text':'','empty_restore_consent':True});self.assertEqual(self.actual,{})
class SourceSafety(unittest.TestCase):
 def test_no_security_policy_change_or_broad_delete(self):
  s=(BASE/'app/firewall.ps1').read_text()
  for x in ('Set-NetFirewallProfile','Set-ExecutionPolicy','netsh','Remove-NetFirewallRule -All','auditpol','Set-NetFirewallSetting'):self.assertNotIn(x,s)
  self.assertIn("$_.Group -ceq $script:group",s);self.assertIn('ownership_mismatch',s);self.assertIn('-Program $j.program',s);self.assertIn('-RemotePort ([string]$entry.port)',s)
 def test_observer_has_no_firewall_or_capture_commands(self):
  s=(BASE/'app/observe.ps1').read_text()
  for x in ('New-NetFirewall','Remove-NetFirewall','auditpol','pktmon','Frida','netsh'):self.assertNotIn(x,s)
  self.assertIn('$live.StartTime.ToUniversalTime().Ticks -ne $owned',s)
 def test_no_automatic_watchdog_or_rollback_after_close(self):
  s=(BASE/'app/main.py').read_text();self.assertNotIn('watchdog',s);self.assertIn("if '--restore' in sys.argv",s)
 def test_no_browser_or_listener(self):
  for file in ('main.py','backend.py','ui.ps1'):self.assertNotIn('HTTPServer',(BASE/'app'/file).read_text())
 def test_launcher_uses_native_window_and_isolated_runtime(self):
  self.assertIn('pythonw.exe',(BASE/'Open.cmd').read_text());self.assertIn('sys.path.insert',(BASE/'app/main.py').read_text())
if __name__=='__main__':unittest.main()
