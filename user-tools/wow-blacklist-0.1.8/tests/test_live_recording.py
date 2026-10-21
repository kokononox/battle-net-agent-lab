import hashlib,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,Manager,BlacklistError,atomic,V4_SPECIAL,V6_SPECIAL,digest
from live_recording import history_baseline,recover_live_labels,clean_baseline
import test_manager as tm
from test_real_powershell import PS,quoted

class LiveBackendTests(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def capture(self,ident='a'*32,**kwargs):
  self.m.collector=lambda p,j:dict(seconds=1,query_errors=0,endpoints=[dict(ip='2.19.198.11',port=80,pid=12,process_started_utc='2026-01-01T00:00:00Z',samples=1,**kwargs)])
  return self.m.run('observe',dict(program=str(self.exe),seconds=60),ident)['observation']
 def test_empty_history_complete_local_only(self):
  r=history_baseline(self.m.captures);self.assertEqual(r['keys'],[]);self.assertTrue(r['complete']);self.assertTrue(r['not_global_history'])
 def test_history_membership_ignores_process_but_keeps_port(self):
  self.capture();r=history_baseline(self.m.captures);self.assertEqual(r['keys'],['2.19.198.11|80|TCP']);self.assertTrue(r['complete']);self.assertEqual(r['files_examined'],1)
 def test_invalid_history_marks_absence_uncertain(self):
  self.capture();self.m.captures.capture_path('b'*32).write_text('bad');r=history_baseline(self.m.captures);self.assertFalse(r['complete']);self.assertEqual(r['invalid_files'],1);self.assertIn('2.19.198.11|80|TCP',r['keys'])
 def test_history_file_limit_marks_incomplete(self):
  self.capture();self.capture('b'*32)
  with patch('live_recording.MAX_HISTORY',1):r=history_baseline(self.m.captures)
  self.assertFalse(r['complete']);self.assertEqual(r['files_examined'],1)
 def test_history_key_limit_marks_incomplete(self):
  self.capture()
  with patch('live_recording.MAX_HISTORY_KEYS',1):r=history_baseline(self.m.captures)
  self.assertFalse(r['complete']);self.assertEqual(len(r['keys']),1)
 def test_truncated_source_not_known_complete(self):
  self.capture();p=self.m.captures.capture_path('a'*32);raw=json.loads(p.read_text());raw['truncated']=True;atomic(p,raw);r=history_baseline(self.m.captures);self.assertFalse(r['complete']);self.assertTrue(r['source_truncated'])
 def test_classification_reports_not_history(self):
  atomic(self.m.output/('destinations-classification-'+'a'*32+'.json'),{});r=history_baseline(self.m.captures);self.assertEqual(r['files_total'],0)
 def test_live_identity_survives_reload_recheck_and_export(self):
  c=self.capture(record_id='c'*32,destination_history='previously_seen',discovery_sequence=1,seen_in_latest_sample=False);row=c['endpoints'][0];self.assertEqual(row['record_id'],'c'*32);self.assertEqual(row['destination_history'],'previously_seen');self.assertFalse(row['seen_in_latest_sample']);self.assertEqual(self.m.captures.read(c['capture_id'])['endpoints'][0]['record_id'],'c'*32)
  r=self.m.run('classify_observation',dict(program=str(self.exe),endpoints=c['endpoints']))['observation'];self.assertEqual(r['endpoints'][0]['destination_history'],'previously_seen');self.assertEqual(r['endpoints'][0]['record_id'],'c'*32)
 def test_live_plan_has_fixed_local_progress_and_policy_only_inventory(self):
  plans=[]
  def collect(p,j):plans.append(p);return dict(endpoints=[])
  self.m.collector=collect;self.m.run('observe',dict(program=str(self.exe),seconds=0),'b'*32);p=plans[0];self.assertEqual(p['seconds'],0);self.assertEqual(p['live_path'],str(self.m.private/('job-'+'b'*32+'.live.json')));self.assertTrue(p['history_baseline']['complete']);self.assertTrue(p['public_exclusions_v4']);self.assertEqual([x['action'] for x in self.calls],['inventory','inventory'])
 def test_live_labels_recovered_on_completion_without_raw_mutation(self):
  def collect(p,j):
   atomic(self.m.private/('job-'+j+'.live-labels.json'),dict(schema='wow-live-labels-1',capture_id=j,entries={'c'*32:'launch'}));return dict(endpoints=[dict(ip='2.19.198.11',port=80,pid=12,record_id='c'*32,samples=1)])
  self.m.collector=collect;r=self.m.run('observe',dict(program=str(self.exe),seconds=60),'a'*32)['observation'];self.assertEqual(r['endpoints'][0]['context']['stage'],'launch');self.assertEqual(r['live_annotation_recovery']['state'],'saved');raw=json.loads(self.m.captures.capture_path('a'*32).read_text());self.assertNotIn('context',raw['endpoints'][0]);self.assertEqual([x['action'] for x in self.calls],['inventory','inventory'])
 def test_bad_journal_preserved_capture_not_lost(self):
  self.capture();p=self.m.private/('job-'+'a'*32+'.live-labels.json');p.write_text('bad');r=recover_live_labels(self.m,'a'*32);self.assertIn('invalid',r['state']);self.assertEqual(p.read_text(),'bad');self.assertEqual(len(self.m.captures.read('a'*32)['endpoints']),1)
 def test_foreign_label_target_does_not_corrupt_annotations(self):
  self.capture(record_id='c'*32);atomic(self.m.private/('job-'+'a'*32+'.live-labels.json'),dict(schema='wow-live-labels-1',capture_id='a'*32,entries={'d'*32:'in_game'}));r=recover_live_labels(self.m,'a'*32);self.assertIn('invalid',r['state']);self.assertFalse(self.m.captures.annotation_path('a'*32).exists())
 def test_baseline_export_excludes_keys(self):
  self.capture();self.capture('b'*32);r=self.m.captures.read('b'*32);self.assertEqual(r['history_baseline']['files_examined'],1);self.assertNotIn('keys',r['history_baseline']);self.assertFalse(clean_baseline(None)['complete'])

@unittest.skipUnless(PS,'Official QA PowerShell runtime required')
class LivePowerShellTests(unittest.TestCase):
 def runps(self,code,**env):return subprocess.run([PS,'-NoProfile','-NonInteractive','-Command',code],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1','WOW_BL_APP':str(BASE/'app'),**env},capture_output=True,timeout=30)
 def test_pulse_semantics_are_samples_not_requests(self):
  code=". ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/ui-live-model.ps1')+"')));$a=[pscustomobject]@{samples=1;seen_in_latest_sample=$true};$b=[pscustomobject]@{samples=2;seen_in_latest_sample=$true};$c=[pscustomobject]@{samples=2;seen_in_latest_sample=$false};@((Live-PulseKind $null $a),(Live-PulseKind $a $b),(Live-PulseKind $b $c),(Live-PulseKind $c $b),(Live-PulseKind $b $b),(Live-DestinationLabel 'previously_seen'),(Live-DestinationLabel 'first_in_local_history'),(Live-DestinationLabel 'history_uncertain'))|ConvertTo-Json -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());values=json.loads(r.stdout);self.assertEqual(values[:5],['discovery','sample','absent','reappeared','none']);self.assertIn('قدیمی',values[5]);self.assertIn('تازه',values[6]);self.assertIn('نامطمئن',values[7])
 def test_live_snapshot_reader_rejects_wrong_capture(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'live.json';atomic(p,dict(schema='wow-live-observation-1',capture_id='a'*32,endpoints=[]))
   code=". ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/ui-live-model.ps1')+"')));try{Live-ReadSnapshot '"+quoted(p)+"' '"+'b'*32+"';exit 8}catch{exit 0}"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode())
 def test_stream_publishes_before_stop_with_old_new_process_and_absence(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');ready=root/'ready';stop=root/'stop';live=root/'live.json';plan=root/'plan.json';ident='a'*32
   atomic(plan,dict(program=str(exe),program_sha256=digest(exe),seconds=0,parent_pid=os.getpid(),ready_path=str(ready),stop_path=str(stop),capture_id=ident,event_evidence_enabled=True,hosts_baseline=dict(available=False,entries=[]),live_path=str(live),history_baseline=dict(keys=['2.19.198.11|80|TCP'],complete=True),public_exclusions_v4=[str(x) for x in V4_SPECIAL],public_exclusions_v6=[str(x) for x in V6_SPECIAL]))
   code=r'''$ErrorActionPreference='Stop';$global:tick=0;$global:old=[DateTime]::Now.AddMinutes(-2);$global:new=[DateTime]::Now.AddSeconds(10)
function Get-Process {param($Id,$Name,$ErrorAction);if($Name){return @([pscustomobject]@{Id=123;Path='__EXE__';StartTime=$global:old},[pscustomobject]@{Id=124;Path='__EXE__';StartTime=$global:new})};if($Id -eq 123){return [pscustomobject]@{Id=123;Path='__EXE__';StartTime=$global:old}};return [pscustomobject]@{Id=124;Path='__EXE__';StartTime=$global:new}}
function Get-NetTCPConnection {$global:tick++;if($global:tick -eq 1){[pscustomobject]@{OwningProcess=123;RemoteAddress='2.19.198.11';RemotePort=80;State='Established'}};[pscustomobject]@{OwningProcess=124;RemoteAddress='3.125.189.135';RemotePort=443;State='SynSent'};[pscustomobject]@{OwningProcess=124;RemoteAddress='10.0.0.1';RemotePort=80;State='Established'}}
& ([scriptblock]::Create([IO.File]::ReadAllText('__SCRIPT__')))
'''.replace('__EXE__',quoted(exe)).replace('__SCRIPT__',quoted(BASE/'app/observe.ps1'))
   proc=subprocess.Popen([PS,'-NoProfile','-NonInteractive','-Command',code],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1','WOW_BL_APP':str(BASE/'app'),'WOW_BL_REQUEST':str(plan)},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    end=time.monotonic()+18;snapshot=None
    while time.monotonic()<end:
     if proc.poll() is not None:break
     try:
      snapshot=json.loads(live.read_text());rows=snapshot['endpoints']
      if len(rows)==2 and rows[1]['samples']>=2:break
     except (OSError,ValueError,KeyError,IndexError):pass
     time.sleep(.05)
    self.assertIsNone(proc.poll(),'collector must remain running until explicit stop');self.assertIsNotNone(snapshot);self.assertEqual(len(rows),2);self.assertEqual(rows[0]['destination_history'],'previously_seen');self.assertFalse(rows[0]['fresh_process_seen']);self.assertFalse(rows[0]['seen_in_latest_sample']);self.assertEqual(rows[1]['destination_history'],'first_in_local_history');self.assertTrue(rows[1]['fresh_process_seen']);self.assertTrue(rows[1]['seen_in_latest_sample']);self.assertFalse(snapshot['finished']);self.assertGreater(snapshot['revision'],1);self.assertEqual(snapshot['live_write_errors'],0)
    ids=[r['record_id'] for r in rows];stop.write_text('stop');out,err=proc.communicate(timeout=10);self.assertEqual(proc.returncode,0,err.decode(errors='replace'));final=json.loads(out);self.assertEqual({r['record_id'] for r in final['endpoints']},set(ids));self.assertTrue(json.loads(live.read_text())['finished'])
   finally:
    if proc.poll() is None:proc.kill();proc.communicate()
 def test_public_filter_and_uncertain_history_status(self):
  code="$j=[pscustomobject]@{history_baseline=[pscustomobject]@{keys=@('2.19.198.11|80|TCP');complete=$false};public_exclusions_v4=@("+','.join("'"+str(x)+"'" for x in V4_SPECIAL)+");public_exclusions_v6=@("+','.join("'"+str(x)+"'" for x in V6_SPECIAL)+")};. ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/observe-live.ps1')+"')));@((Test-LivePublic '2.19.198.11'),(Test-LivePublic '10.0.0.1'),(Test-LivePublic '127.0.0.2'),(Test-LivePublic '224.0.0.1'),(Test-LivePublic '2606:4700:4700::1111'),(Test-LivePublic 'fc00::1'),(Live-HistoryStatus '2.19.198.11' 80),(Live-HistoryStatus '2.19.198.11' 443))|ConvertTo-Json -Compress"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(json.loads(r.stdout),[True,False,False,False,True,False,'previously_seen','history_uncertain'])

class LiveUiContracts(unittest.TestCase):
 def test_topmost_optional_and_nonmodal_no_focus_stealing_on_updates(self):
  s=(BASE/'app/ui-live.ps1').read_text();self.assertIn('$w.TopMost=$true',s);self.assertIn('$script:liveForm.TopMost=$script:liveTop.Checked',s);self.assertNotIn('.Activate(',s);self.assertNotIn('.ShowDialog(',s);self.assertIn('$sender.Hide()',s)
 def test_live_controls_not_disabled_by_main_busy(self):
  s=(BASE/'app/ui.ps1').read_text();controls=s.split('$script:controls=@(',1)[1].split(')',1)[0];self.assertNotIn('$liveOpen',controls);self.assertNotIn('$liveEnabled',controls);self.assertIn('Poll-LiveCapture $j',s);self.assertIn('Finish-LiveCapture $r.observation',s)
 def test_all_rows_no_old_or_block_filters_and_disable_flash(self):
  s=(BASE/'app/ui-live.ps1').read_text();self.assertIn('foreach($e in @($snapshot.endpoints))',s);self.assertNotIn('onlyFresh',s);self.assertNotIn('hideCovered',s);self.assertIn('$script:liveFlash.Checked',s);self.assertIn('$script:livePause.Checked',s);self.assertIn('فریم زنده بیش از ۴ ثانیه',s)
 def test_manual_stage_journal_and_final_overlay(self):
  s=(BASE/'app/ui-live.ps1').read_text();self.assertIn('wow-live-labels-1',s);self.assertIn('function Finish-LiveCapture',s);self.assertIn('$script:annotationsDirty=$true',s);self.assertIn('function Sync-LiveStageFromMain',s)
 def test_collector_and_live_code_no_rule_mutations_or_dns(self):
  s='\n'.join((BASE/'app'/n).read_text() for n in ('observe.ps1','observe-live.ps1','ui-live.ps1','ui-live-model.ps1'))
  for name in ('New-NetFirewallRule','Remove-NetFirewallRule','Resolve-DnsName','Invoke-WebRequest','SendKeys'):self.assertNotIn(name,s)

if __name__=='__main__':unittest.main()
