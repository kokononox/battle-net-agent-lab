import json,sys,os,subprocess,tempfile,unittest,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,atomic
from event_evidence import normalize_evidence,hosts_baseline
import test_manager as tm
from test_real_powershell import PS,quoted

def dns(**kw):return dict(record_id='c'*32,kind='dns_query',observed_utc='2026-01-01T00:00:00Z',pid=12,event_record_id=1,domain='Telemetry.Example.',dns_status='0',query_results='127.0.0.1;',hosts_mapping='local_sink_mapping',hosts_addresses=['127.0.0.1'],**kw)
def block(**kw):return dict(record_id='d'*32,kind='wfp_connection_block',observed_utc='2026-01-01T00:00:00Z',pid=12,event_record_id=2,ip='2.19.198.11',port=80,protocol='TCP',direction='outbound',filter_id='123',**kw)
class EvidenceSanitization(unittest.TestCase):
 def test_dns_attempt_not_equivalent_to_http_or_hosts_proof(self):
  r=normalize_evidence(dict(events=[dns()]));e=r['events'][0];self.assertEqual(e['domain'],'telemetry.example');self.assertFalse(e['hosts_block_verified']);self.assertFalse(e['HTTP_request_verified']);self.assertEqual(e['source'],'Sysmon_22')
 def test_actual_wfp_connection_event_not_owner_or_packet_proof(self):
  e=normalize_evidence(dict(events=[block()]))['events'][0];self.assertTrue(e['connection_block_event_verified']);self.assertFalse(e['rule_owner_verified']);self.assertFalse(e['packet_drop_verified'])
 def test_reject_invalid_identity_time_or_event_kind(self):
  for changes in (dict(record_id='../escape'),dict(observed_utc='no'),dict(pid=0),dict(kind='inferred_ptr_attempt')):
   self.assertEqual(normalize_evidence(dict(events=[{**dns(),**changes}]))['events'],[])
 def test_wfp_inbound_and_invalid_protocol_not_presented_as_outbound_attempt(self):
  for changes in (dict(direction='inbound'),dict(protocol='ICMP'),dict(port=0),dict(ip='not-ip')):
   self.assertEqual(normalize_evidence(dict(events=[{**block(),**changes}]))['events'],[])
 def test_private_loopback_block_events_can_be_evidence(self):
  r=normalize_evidence(dict(events=[{**block(),'ip':'127.0.0.1'}]));self.assertEqual(len(r['events']),1)
 def test_full_image_owner_and_raw_xml_not_exported(self):
  e={**dns(),'Image':'C:/Private/Wow.exe','Application':'\\Device\\Private\\Wow.exe','owner':'private-owner','xml':'raw'};text=json.dumps(normalize_evidence(dict(events=[e])));self.assertNotIn('Private',text);self.assertNotIn('private-owner',text);self.assertNotIn('raw',text)
 def test_duplicate_ids_suppressed_and_missing_sources_unavailable(self):
  r=normalize_evidence(dict(events=[dns(),dns()]));self.assertEqual(len(r['events']),1);self.assertEqual(r['streams']['dns']['status'],'not_collected');self.assertFalse(r['streams']['wfp']['coverage_verified'])
 def test_unknown_hosts_not_claimed_absent(self):
  e=normalize_evidence(dict(events=[{**dns(),'hosts_mapping':'guess'}]))['events'][0];self.assertEqual(e['hosts_mapping'],'hosts_unavailable')
 def test_query_results_bounded(self):
  e=normalize_evidence(dict(events=[{**dns(),'query_results':'x'*9000}]))['events'][0];self.assertEqual(len(e['query_results']),2000)
 def test_hosts_failure_read_only_baseline(self):
  r=hosts_baseline(lambda:(_ for _ in ()).throw(OSError()));self.assertFalse(r['available']);self.assertEqual(r['entries'],[])

class EvidenceCaptureTests(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def capture(self):
  self.m.collector=lambda p,j:dict(endpoints=[],event_evidence=dict(events=[dns(),block()],streams=dict(dns=dict(status='readable_logging_coverage_unverified'),wfp=dict(status='readable_logging_coverage_unverified'))))
  return self.m.run('observe',dict(program=str(self.exe),seconds=60),'a'*32)['observation']
 def test_events_without_tcp_rows_still_captured(self):
  r=self.capture();self.assertEqual(r['endpoints'],[]);self.assertEqual(len(r['event_evidence']['events']),2);self.assertEqual(r['event_evidence']['events'][0]['context']['stage'],'unknown')
 def test_manual_stages_for_dns_and_block_events(self):
  self.capture();self.m.captures.save_annotations('a'*32,{'c'*32:'launch','d'*32:'login'});r=self.m.captures.read('a'*32);self.assertEqual([e['context']['stage'] for e in r['event_evidence']['events']],['launch','login'])
 def test_history_counts_event_records(self):
  self.capture();r=self.m.captures.history()['entries'][0];self.assertEqual(r['records'],2);self.assertEqual(r['evidence_records'],2)
 def test_events_export_with_separate_active_list_and_no_paths(self):
  self.capture();self.m.captures.save_annotations('a'*32,{'c'*32:'launch'});r=self.m.run('export_analysis',dict(capture_ids=['a'*32],program=str(self.exe)),'e'*32)['export'];self.assertEqual(r['record_count'],2)
  with zipfile.ZipFile(self.m.output/r['filename']) as z:
   data=json.loads(z.read('analysis.json'));text=z.read('report.fa.txt').decode();self.assertIn('telemetry.example',text);self.assertIn('WFP',text);self.assertNotIn(str(self.exe),text);self.assertEqual(data['captures'][0]['event_evidence']['events'][0]['context']['stage'],'launch');self.assertFalse(data['privacy']['hosts_contents_included']);self.assertTrue(data['privacy']['attempted_domain_hosts_mappings_included'])
 def test_raw_capture_is_not_modified_by_event_annotations(self):
  self.capture();p=self.m.captures.capture_path('a'*32);before=p.read_bytes();self.m.captures.save_annotations('a'*32,{'c'*32:'in_game'});self.assertEqual(p.read_bytes(),before)

@unittest.skipUnless(PS,'Official QA PowerShell runtime required')
class EvidencePowerShell(unittest.TestCase):
 def runps(self,code):return subprocess.run([PS,'-NoProfile','-NonInteractive','-Command',code],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1'},capture_output=True,timeout=30)
 def script(self):return quoted(BASE/'app/observe-events.ps1')
 def mock(self,available=True):
  return r'''
$ErrorActionPreference='Stop';$start=[DateTime]::UtcNow.AddSeconds(-10)
$j=[pscustomobject]@{program='C:\Games\Wow.exe';program_device_path='\Device\HarddiskVolume2\Games\Wow.exe';hosts_baseline=[pscustomobject]@{available=$true;truncated=$false;entries=@([pscustomobject]@{domain='telemetry.example';addresses=@('0.0.0.0');mapping_kind='local_sink_mapping'})}}
$global:dnsXml='<Event><EventData><Data Name="ProcessId">123</Data><Data Name="Image">C:\Games\Wow.exe</Data><Data Name="QueryName">telemetry.example</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">0.0.0.0;</Data></EventData></Event>'
$global:blockXml='<Event><EventData><Data Name="ProcessID">0x7b</Data><Data Name="Application">\Device\HarddiskVolume2\Games\Wow.exe</Data><Data Name="Direction">%%14593</Data><Data Name="DestAddress">2.19.198.11</Data><Data Name="DestPort">80</Data><Data Name="Protocol">6</Data><Data Name="FilterRTID">321</Data></EventData></Event>'
function Get-WinEvent {param($ListLog,$FilterHashtable,$MaxEvents,$ErrorAction);if($ListLog){return [pscustomobject]@{IsEnabled=$true}};$source=if($FilterHashtable.Id -eq 22){'dns'}else{'wfp'};$ev=[pscustomobject]@{RecordId=1;TimeCreated=[DateTime]::UtcNow;ProviderName=$(if($source -eq 'dns'){'Microsoft-Windows-Sysmon'}else{'Microsoft-Windows-Security-Auditing'});Raw=$(if($source -eq 'dns'){$global:dnsXml}else{$global:blockXml})};$ev|Add-Member -MemberType ScriptMethod -Name ToXml -Value {return $this.Raw};return $ev}
'''
 def test_existing_logs_match_exact_application_and_hosts_is_only_mapping(self):
  code=self.mock()+". ([scriptblock]::Create([IO.File]::ReadAllText('"+self.script()+"')));Update-EventEvidence;Update-EventEvidence $true;Event-Evidence|ConvertTo-Json -Depth 10 -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());data=json.loads(r.stdout);self.assertEqual(len(data['events']),2);dnsrow,blockrow=data['events'];self.assertEqual(dnsrow['domain'],'telemetry.example');self.assertEqual(dnsrow['hosts_mapping'],'local_sink_mapping');self.assertEqual(blockrow['kind'],'wfp_connection_block');self.assertEqual(blockrow['pid'],123);self.assertEqual(blockrow['ip'],'2.19.198.11');self.assertNotIn('Image',dnsrow);self.assertFalse(data['configuration_changed'])
 def test_foreign_application_paths_not_attributed_to_wow(self):
  code=self.mock()+"$global:dnsXml=$global:dnsXml.Replace('C:\\Games\\Wow.exe','C:\\Games\\Other.exe');$global:blockXml=$global:blockXml.Replace('\\Device\\HarddiskVolume2\\Games\\Wow.exe','\\Device\\HarddiskVolume2\\Games\\Other.exe');. ([scriptblock]::Create([IO.File]::ReadAllText('"+self.script()+"')));Update-EventEvidence;Event-Evidence|ConvertTo-Json -Depth 10 -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(json.loads(r.stdout)['events'],[])
 def test_logs_disabled_report_unavailable_without_enabling(self):
  code=self.mock()+"function Get-WinEvent {param($ListLog,$FilterHashtable,$MaxEvents,$ErrorAction);if($ListLog){return [pscustomobject]@{IsEnabled=$false}};throw 'unexpected_read'};. ([scriptblock]::Create([IO.File]::ReadAllText('"+self.script()+"')));Update-EventEvidence;Event-Evidence|ConvertTo-Json -Depth 10 -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());data=json.loads(r.stdout);self.assertEqual(data['events'],[]);self.assertEqual(data['streams']['dns']['status'],'not_available_or_disabled')
 def test_inbound_event_does_not_become_outbound_block(self):
  code=self.mock()+"$global:blockXml=$global:blockXml.Replace('%%14593','%%14592');. ([scriptblock]::Create([IO.File]::ReadAllText('"+self.script()+"')));Update-EventEvidence;Event-Evidence|ConvertTo-Json -Depth 10 -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());data=json.loads(r.stdout);self.assertEqual(len(data['events']),1);self.assertEqual(data['events'][0]['kind'],'dns_query')
 def test_live_evidence_labels_never_say_unobserved_is_allowed(self):
  code=". ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/ui-live-model.ps1')+"')));@((Live-EvidenceLabel ([pscustomobject]@{kind='dns_query';hosts_mapping='local_sink_mapping'})),(Live-EvidenceLabel ([pscustomobject]@{kind='wfp_connection_block'})),(Live-StreamLabel $null))|ConvertTo-Json -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());labels=json.loads(r.stdout);self.assertIn('اثر تأییدنشده',labels[0]);self.assertIn('منع اتصال ثبت‌شده',labels[1]);self.assertIn('در دسترس نیست',labels[2])

class EvidenceSafety(unittest.TestCase):
 def test_never_installs_or_enables_audit_or_executes_bat(self):
  s=(BASE/'app/observe-events.ps1').read_text()
  for command in ('auditpol','wevtutil','Set-WinEvent','Start-Process','cmd.exe','sysmon.exe','New-NetFirewallRule','Remove-NetFirewallRule'):self.assertNotIn(command,s)
 def test_event_scope_does_not_use_provider_execution_pid(self):
  s=(BASE/'app/observe-events.ps1').read_text();self.assertIn('$d.ProcessId',s);self.assertIn('$d.Application',s);self.assertNotIn('Execution.ProcessID',s)


def test_wfp_attempts_also_count_as_prior_destinations(self):
 from live_recording import history_baseline
 self.capture();r=history_baseline(self.m.captures);self.assertIn('2.19.198.11|80|TCP',r['keys'])
EvidenceCaptureTests.test_wfp_attempts_also_count_as_prior_destinations=test_wfp_attempts_also_count_as_prior_destinations

if __name__=='__main__':unittest.main()
