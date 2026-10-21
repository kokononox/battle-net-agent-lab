import datetime,hashlib,ipaddress,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import Manager,BlacklistError,BASE,atomic,parse_list,spec,digest
from hosts_view import parse_hosts,read_windows_hosts,MAX_BYTES
from observation_model import normalize_rows,classify_rows,timestamp
import test_manager as tm
import test_real_powershell as tp

class EvidenceTests(unittest.TestCase):
 def row(self,**kw):return dict(ip='2.19.198.11',port=80,pid=12,process_started_utc='2026-01-01T00:00:00Z',fresh_process_seen=True,samples=2,state_samples={'SynSent':1,'Established':1},**kw)
 def test_state_history_not_packet_or_current_connection_claim(self):
  rows=normalize_rows([self.row()]);self.assertTrue(rows[0]['established_seen']);self.assertTrue(rows[0]['syn_sent_seen']);r=classify_rows(rows,dict(available=True,entries=[]))[0];self.assertFalse(r['packet_drop_verified']);self.assertEqual(r['block_classification'],'no_verified_match')
 def test_same_endpoint_old_and_new_process_remain_separate(self):
  a=self.row();b={**a,'pid':13,'fresh_process_seen':False};rows=normalize_rows([a,b]);self.assertEqual(len(rows),2);self.assertEqual([x['fresh_process_seen'] for x in rows],[True,False])
 def test_reused_pid_with_new_start_time_remains_separate(self):
  a=self.row();b={**a,'process_started_utc':'2026-01-02T00:00:00Z'};self.assertEqual(len(normalize_rows([a,b])),2)
 def test_match_exact_protocol_port_and_range(self):
  rows=normalize_rows([self.row()]);base=dict(available=True,checked_utc='now',entries=parse_list('2.0.0.0/8:80 TCP'));r=classify_rows(rows,base)[0];self.assertTrue(r['covered_by_verified_block']);self.assertEqual(r['block_matches'][0]['ip'],'2.0.0.0/8');self.assertFalse(r['packet_drop_verified'])
  for text in ('2.0.0.0/8:80 UDP','2.0.0.0/8:443 TCP','3.0.0.0/8:80 TCP'):
   r=classify_rows(rows,dict(available=True,entries=parse_list(text)))[0];self.assertFalse(r['covered_by_verified_block'])
 def test_unavailable_snapshot_never_hides_even_if_entries_present(self):
  rows=normalize_rows([self.row()]);r=classify_rows(rows,dict(available=False,entries=parse_list('2.0.0.0/8:80 TCP')))[0];self.assertFalse(r['covered_by_verified_block']);self.assertEqual(r['block_classification'],'unverified')
 def test_private_multicast_bad_port_and_bad_pid_rejected(self):
  a=self.row();bad=[{**a,'ip':'127.0.0.1'},{**a,'ip':'10.0.0.1'},{**a,'ip':'224.0.0.1'},{**a,'port':0},{**a,'pid':-1},{**a,'state_samples':[],'samples':1}];self.assertEqual(normalize_rows(bad),[])
 def test_unknown_state_not_invented_as_established(self):
  a=self.row();a['state_samples']={'made_up':1};r=normalize_rows([a])[0];self.assertEqual(r['state_samples'],{'Unknown':2});self.assertFalse(r['established_seen'])
 def test_timestamp_must_have_timezone(self):
  self.assertEqual(timestamp('2026-01-01T00:00:00'),'');self.assertEqual(timestamp('not-date'),'');self.assertTrue(timestamp('2026-01-01T02:00:00+02:00').startswith('2026-01-01T00:00:00'))

class HostsTests(unittest.TestCase):
 def test_common_sink_mappings_are_not_claimed_as_proven_blocking(self):
  r=parse_hosts(b'0.0.0.0 blocked.example\n127.0.0.1 blocked2.example\n::1 blocked3.example\n:: blocked4.example\n')
  self.assertEqual(r['local_sink_domains'],4);self.assertTrue(r['read_only']);self.assertFalse(r['game_attempt_verified']);self.assertFalse(r['blocking_verified'])
 def test_aliases_comments_duplicates_and_line_numbers(self):
  r=parse_hosts(b'# comment\n0.0.0.0 A.EXAMPLE b.example # off\n0.0.0.0 a.example\n');self.assertEqual(len(r['entries']),2);self.assertEqual(r['entries'][0]['domain'],'a.example');self.assertEqual(r['entries'][0]['lines'],[2,3]);self.assertEqual(r['entries'][0]['addresses'],['0.0.0.0'])
 def test_mixed_ipv4_ipv6_or_other_mapping_gets_conflict_label(self):
  r=parse_hosts(b'0.0.0.0 mixed.example\n2606:4700::1111 mixed.example\n8.8.8.8 normal.example\n');self.assertEqual(r['mixed_domains'],1);self.assertEqual(r['entries'][0]['mapping_kind'],'mixed_mapping');self.assertEqual(r['entries'][1]['mapping_kind'],'other_mapping')
 def test_localhost_is_not_treated_as_site_blocked_by_user(self):
  r=parse_hosts(b'127.0.0.1 localhost\n::1 localhost\n');self.assertEqual(r['local_sink_domains'],0);self.assertEqual(r['entries'][0]['mapping_kind'],'system_local')
 def test_bad_entries_do_not_become_domains(self):
  r=parse_hosts(b'garbage example.com\n0.0.0.0 <script> valid.example\n0.0.0.0\n');self.assertEqual([x['domain'] for x in r['entries']],['valid.example']);self.assertGreater(r['invalid_items'],0)
 def test_utf8_bom_and_utf16(self):
  for raw in ('\ufeff0.0.0.0 test.example\n'.encode('utf-8'),'0.0.0.0 test.example\n'.encode('utf-16')):
   self.assertEqual(parse_hosts(raw)['entries'][0]['domain'],'test.example')
 def test_cp1252_comment_fallback(self):
  r=parse_hosts(b'# caf\xe9\n0.0.0.0 test.example');self.assertEqual(r['encoding'],'cp1252');self.assertEqual(len(r['entries']),1)
 def test_file_size_limit(self):
  with self.assertRaisesRegex(ValueError,'too_large'):parse_hosts(b'X'*(MAX_BYTES+1))
 def test_truncation_is_explicit(self):
  with patch('hosts_view.MAX_DOMAINS',2):r=parse_hosts(b'0.0.0.0 a.example b.example c.example')
  self.assertTrue(r['truncated']);self.assertEqual(len(r['entries']),2)
 def test_reader_never_writes_hosts_or_takes_payload_path(self):
  with tempfile.TemporaryDirectory() as t:
   path=Path(t)/'System32/drivers/etc/hosts';path.parent.mkdir(parents=True);raw=b'0.0.0.0 test.example\n';path.write_bytes(raw)
   with patch('hosts_view.IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':t}):r=read_windows_hosts()
   self.assertEqual(path.read_bytes(),raw);self.assertEqual(r['sha256'],hashlib.sha256(raw).hexdigest())

class EvidenceManagerTests(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def inventory_fw(self,entries,available=True):
  def fw(plan,job):
   self.calls.append(plan)
   return dict(inventory_verified=available,entries=[spec(self.m.owner(),str(self.exe),e) for e in entries],checked_utc='2026-01-01T00:00:00Z',unverified_owned_count=0)
  self.m.fw=fw
 def capture(self):
  self.m.collector=lambda plan,job:dict(endpoints=[dict(ip='2.19.198.11',port=80,pid=12,process_started_utc='2026-01-01T00:00:00Z',fresh_process_seen=True,samples=1,state_samples={'SynSent':1})],query_errors=0,seconds=1)
  return self.m.run('observe',dict(program=str(self.exe),seconds=60))['observation']
 def test_saved_but_not_applied_is_not_evidence_of_block(self):
  self.m.run('save',{**self.payload,'text':'2.0.0.0/8:80 TCP'});self.calls.clear();self.inventory_fw([]);r=self.capture();self.assertFalse(r['endpoints'][0]['covered_by_verified_block']);self.assertEqual([x['action'] for x in self.calls],['inventory','inventory'])
 def test_actual_owned_rules_used_even_when_desired_list_differs(self):
  self.inventory_fw(parse_list('2.0.0.0/8:80 TCP'));r=self.capture();self.assertTrue(r['endpoints'][0]['covered_by_verified_block']);self.assertNotIn('owner',json.dumps(r));self.assertNotIn(str(self.exe),json.dumps(r))
 def test_failed_inventory_does_not_discard_capture(self):
  self.m.fw=lambda p,j:(_ for _ in ()).throw(BlacklistError('fixture'));r=self.capture();self.assertEqual(len(r['endpoints']),1);self.assertFalse(r['block_snapshot']['available']);self.assertEqual(r['endpoints'][0]['block_classification'],'unverified')
 def test_tampered_rule_name_not_trusted(self):
  self.m.fw=lambda p,j:dict(inventory_verified=True,entries=[dict(ip='2.0.0.0/8',port=80,protocol='TCP',name='WoWBlacklist-'+self.m.owner()+'-'+'0'*24)])
  r=self.capture();self.assertFalse(r['endpoints'][0]['covered_by_verified_block']);self.assertEqual(r['block_snapshot']['unverified_owned_count'],1)
 def test_reclassification_preserves_tcp_evidence_and_settings(self):
  self.inventory_fw(parse_list('2.0.0.0/8:80 TCP'));r=self.capture();before=self.m.config_path.read_bytes();txt=self.m.text_path.read_bytes();self.calls.clear()
  self.inventory_fw([]);new=self.m.run('classify_observation',dict(program=str(self.exe),endpoints=r['endpoints']))['observation']
  self.assertFalse(new['endpoints'][0]['covered_by_verified_block']);self.assertEqual(new['endpoints'][0]['state_samples'],{'SynSent':1});self.assertEqual(self.m.config_path.read_bytes(),before);self.assertEqual(self.m.text_path.read_bytes(),txt);self.assertEqual([p['action'] for p in self.calls],['inventory'])
 def test_hosts_action_is_readonly_and_independent_of_owner(self):
  for p in self.m.private.glob('owner-id*'):p.unlink()
  before=self.m.config_path.read_bytes();self.m.hosts_reader=lambda:parse_hosts(b'0.0.0.0 test.example\n');r=self.m.run('hosts',dict(path='C:/not-allowed'))
  self.assertEqual(r['hosts']['entries'][0]['domain'],'test.example');self.assertEqual(self.calls,[]);self.assertEqual(self.m.config_path.read_bytes(),before)
 def test_hosts_read_failure_has_no_firewall_side_effect(self):
  self.m.hosts_reader=lambda:(_ for _ in ()).throw(OSError('fixture'))
  with self.assertRaisesRegex(BlacklistError,'hosts_read_failed'):self.m.run('hosts')
  self.assertEqual(self.calls,[])

# Extend the existing mock Windows filters with defaults relevant to a conservative inventory.
EXTRA_FILTERS=r'''
function Get-NetFirewallApplicationFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{Program=$InputObject.Program;Package='Any'}}}
function Get-NetFirewallAddressFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{RemoteAddress=$InputObject.IP;LocalAddress='Any'}}}
function Get-NetFirewallPortFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{RemotePort=$InputObject.Port;Protocol=$InputObject.Protocol;LocalPort='Any'}}}
function Get-NetFirewallInterfaceFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{InterfaceAlias='Any'}}}
function Get-NetFirewallInterfaceTypeFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{InterfaceType='Any'}}}
function Get-NetFirewallServiceFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{Service='Any'}}}
function Get-NetFirewallSecurityFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{LocalUser='Any';RemoteUser='Any';RemoteMachine='Any';Authentication='NotRequired';Encryption='NotRequired'}}}
'''
@unittest.skipUnless(tp.PS,'PowerShell QA runtime required')
class EvidencePowerShellTests(unittest.TestCase):
 env=tp.RealPowerShell.env
 runps=tp.RealPowerShell.runps
 def test_inventory_is_readonly_and_rejects_disabled_or_changed_rules(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');owner='a'*32;entries=[spec(owner,str(exe),e) for e in parse_list('2.0.0.0/8:80 TCP\n8.8.8.8:53 UDP')]
   apply=root/'a.json';inventory=root/'i.json';atomic(apply,dict(owner=owner,program=str(exe),action='apply',entries=entries));atomic(inventory,dict(owner=owner,program=str(exe),action='inventory',entries=[]));script=tp.quoted(BASE/'app/firewall.ps1')
   def invoke(path):return "$env:WOW_BL_REQUEST='"+tp.quoted(path)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+script+"')))\n"
   code=tp.MOCKS+EXTRA_FILTERS+invoke(apply)+invoke(inventory)+"$global:store['"+entries[0]['name']+"'].Enabled='False'\n"+invoke(inventory)+"if($global:adds -ne 2 -or $global:removes -ne 0){throw 'inventory_mutated'}"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'));out=[json.loads(x) for x in r.stdout.decode('utf-8-sig').splitlines() if x.startswith('{')]
   self.assertEqual(len(out[1]['entries']),2);self.assertEqual(len(out[2]['entries']),1);self.assertEqual(out[2]['unverified_owned_count'],1)
 def test_inventory_does_not_verify_interface_restricted_rule(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');owner='b'*32;entry=spec(owner,str(exe),parse_list('2.0.0.0/8:80 TCP')[0]);a=root/'a.json';b=root/'b.json';atomic(a,dict(owner=owner,program=str(exe),action='apply',entries=[entry]));atomic(b,dict(owner=owner,program=str(exe),action='inventory',entries=[]));script=tp.quoted(BASE/'app/firewall.ps1')
   code=tp.MOCKS+EXTRA_FILTERS+"$env:WOW_BL_REQUEST='"+tp.quoted(a)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+script+"')));function Get-NetFirewallInterfaceFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{InterfaceAlias='Restricted'}}};$env:WOW_BL_REQUEST='"+tp.quoted(b)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+script+"')))"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));out=json.loads(r.stdout.decode('utf-8-sig').splitlines()[-1]);self.assertEqual(out['entries'],[]);self.assertEqual(out['unverified_owned_count'],1)
 def test_pure_ui_partition_preserves_all_evidence_and_restores_views(self):
  model=tp.quoted(BASE/'app/ui-model.ps1')
  code=". ([scriptblock]::Create([IO.File]::ReadAllText('"+model+"')));$rows=@([pscustomobject]@{id=1;fresh_process_seen=$true;covered_by_verified_block=$false},[pscustomobject]@{id=2;fresh_process_seen=$true;covered_by_verified_block=$true},[pscustomobject]@{id=3;fresh_process_seen=$false;covered_by_verified_block=$true});$a=Ui-ObservationPartition $rows $true $true;if(@($a.main).Count -ne 1 -or @($a.covered).Count -ne 1 -or $a.old_hidden -ne 1){throw 'default_partition'};$b=Ui-ObservationPartition $rows $false $false;if(@($b.main).Count -ne 3 -or @($b.covered).Count -ne 2 -or $rows.Count -ne 3){throw 'lost_evidence'}"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
 def test_observer_records_state_and_separates_old_new_processes(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');plan=root/'p.json';ready=root/'ready';stop=root/'stop';atomic(plan,dict(program=str(exe),program_sha256=digest(exe),seconds=60,parent_pid=os.getpid(),ready_path=str(ready),stop_path=str(stop)))
   # One sample is sufficient; mocked sleep requests stop after the first query.
   code="$global:old=[DateTime]::Now.AddMinutes(-10);$global:new=[DateTime]::Now.AddSeconds(1);function Get-Process {param($Id,$Name,$ErrorAction);if($Name){@([pscustomobject]@{Id=11;Path='"+tp.quoted(exe)+"';StartTime=$global:old},[pscustomobject]@{Id=12;Path='"+tp.quoted(exe)+"';StartTime=$global:new})}else{[pscustomobject]@{Id=$Id;Path='"+tp.quoted(exe)+"';StartTime=$(if($Id -eq 11){$global:old}else{$global:new})}}};function Get-NetTCPConnection {@([pscustomobject]@{OwningProcess=11;RemoteAddress='2.19.198.11';RemotePort=80;State='Established'},[pscustomobject]@{OwningProcess=12;RemoteAddress='2.19.198.11';RemotePort=80;State='SynSent'})};function Start-Sleep {param($Milliseconds);[IO.File]::WriteAllText('"+tp.quoted(stop)+"','stop')};$env:WOW_BL_REQUEST='"+tp.quoted(plan)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+tp.quoted(BASE/'app/observe.ps1')+"')))"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'));raw=json.loads(r.stdout.decode('utf-8-sig'));rows=sorted(raw['endpoints'],key=lambda x:x['pid']);self.assertEqual(len(rows),2);self.assertFalse(rows[0]['fresh_process_seen']);self.assertTrue(rows[1]['fresh_process_seen']);self.assertEqual(rows[0]['state_samples'],{'Established':1});self.assertEqual(rows[1]['state_samples'],{'SynSent':1})

class EvidenceUiContracts(unittest.TestCase):
 def test_filters_default_to_full_capture_and_not_data_deletion(self):
  s=(BASE/'app/ui.ps1').read_text();model=(BASE/'app/ui-observation.ps1').read_text();self.assertIn('$onlyFresh.Checked=$false',s);self.assertIn('$hideCovered.Checked=$false',s);self.assertIn('Ui-ObservationPartition $script:observed',model);self.assertIn('Add-ObservedRow $covered $e',model);self.assertNotIn('$script:observed=@()',model)
 def test_hosts_is_readonly_with_no_auto_resolve_or_apply(self):
  s=(BASE/'app/hosts_view.py').read_text();self.assertNotIn('.write_',s);self.assertNotIn('socket',s);self.assertNotIn('subprocess',s);ui=(BASE/'app/ui.ps1').read_text();self.assertIn("BeginOp 'hosts' @{}",ui);self.assertIn("$hostsGrid=Grid",ui)
 def test_reclassification_is_invalidated_on_mutation(self):
  s=(BASE/'app/ui.ps1').read_text();self.assertIn("if($j.Action -in @('apply','restore')){Invalidate-ObservationClassification}",s);self.assertIn("BeginOp 'classify_observation'",s)
 def test_readonly_errors_do_not_claim_partial_firewall_changes(self):
  s=(BASE/'app/ui.ps1').read_text();self.assertIn("if(!$r.ok -and $j.Action -in @('hosts','observe','classify_observation','history','load_observation','annotate_observation','export_analysis','hosts_apply','delete_records','delete_captures','compare_captures'))",s)

if __name__=='__main__':unittest.main()
