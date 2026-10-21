"""Session phase sampling, read-only comparison, health and compact UI regression."""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,BlacklistError,atomic,digest
from phase_context import clean_recording,clean_hits,attach_phases,phase_at
from capture_compare import compare,group_rows
import test_manager as tm
import test_analysis_export as analysis_tests
from test_event_evidence import dns,block
from test_real_powershell import PS,quoted
T0='2026-01-01T00:00:00Z';T1='2026-01-01T00:00:01Z';T2='2026-01-01T00:00:02Z';T3='2026-01-01T00:00:03Z';T9='2026-01-01T00:01:00Z'
def timeline(errors=0):return dict(schema='wow-stage-recording-1',read_errors=errors,transitions=[dict(sequence=i,stage=stage,selected_utc=t) for i,stage,t in [(1,'launch',T0),(2,'login',T2),(3,'in_game',T3)]])
def hit(code='launch',first=T1,last=T1,n=1):return {code:dict(samples=n,first_seen_utc=first,last_seen_utc=last)}
def endpoint(**kw):return dict(ip='2.19.198.11',port=80,pid=12,process_started_utc=T0,samples=2,state_samples={'SynSent':1,'Established':1},first_seen_utc=T1,last_seen_utc=T3,**kw)
class PhaseModel(unittest.TestCase):
 def test_timeline_and_boundary(self):
  r=clean_recording(timeline(),T0,T9);self.assertEqual(r['status'],'available');self.assertEqual(phase_at(r['transitions'],T2),'login');self.assertEqual(phase_at(r['transitions'],'2025-12-31T23:59:59Z'),'unknown')
 def test_unknown_resets_phase(self):
  r=timeline();r['transitions'][1]['stage']='unknown';self.assertEqual(phase_at(clean_recording(r,T0,T9)['transitions'],T2),'unknown')
 def test_bad_timelines_rejected(self):
  for edit in ({'stage':'bogus'},{'sequence':4},{'selected_utc':'2026-01-01T00:00:02'},{'selected_utc':'2026-01-02T00:00:00Z'},{'selected_utc':'2025-12-01T00:00:00Z'}):
   r=timeline();r['transitions'][1].update(edit);self.assertEqual(clean_recording(r,T0,T9)['status'],'invalid')
 def test_caps_order_and_types(self):
  for entries in ([{}]*501,[None],['bad']):
   self.assertEqual(clean_recording(dict(schema='wow-stage-recording-1',transitions=entries),T0,T9)['status'],'invalid')
  r=timeline();r['transitions'][2]['selected_utc']=T1;self.assertEqual(clean_recording(r,T0,T9)['status'],'invalid')
 def test_legacy_and_invalid_not_reinterpreted(self):
  self.assertEqual(clean_recording(None)['status'],'not_recorded');self.assertEqual(clean_recording({'status':'invalid'})['status'],'invalid')
 def test_strict_hit_bounds_and_sample_count(self):
  self.assertEqual(len(clean_hits(hit(),T1,T3,2)),1)
  for h in (hit(n=3),hit(first=T0),hit(last=T9),{'launch':None},hit(n=True),{'fake':hit()['launch']}):self.assertEqual(clean_hits(h,T1,T3,2),{})
 def capture(self,recording=None,hits=None):return dict(capture_started_utc=T0,capture_ended_utc=T9,phase_recording=recording or {},endpoints=[endpoint(phase_hits=hits or {})],event_evidence=dict(events=[{**dns(),'observed_utc':T2}]))
 def test_no_stage_inferred_from_first_last_span(self):
  c=attach_phases(self.capture(clean_recording(timeline(),T0,T9),hit()));self.assertEqual(c['endpoints'][0]['phase_context']['stages'],['launch']);self.assertFalse(c['endpoints'][0]['phase_context']['continuous_presence_verified'])
 def test_event_uses_event_timestamp_not_delivery(self):
  c=attach_phases(self.capture(clean_recording(timeline(),T0,T9)));self.assertEqual(c['event_evidence']['events'][0]['phase_context']['stages'],['login'])
 def test_events_outside_recording_unknown(self):
  c=self.capture(clean_recording(timeline(),T0,T9));c['event_evidence']['events'][0]['observed_utc']='2026-01-02T00:00:00Z';self.assertEqual(attach_phases(c)['event_evidence']['events'][0]['phase_context']['stages'],[])
 def test_journal_errors_disable_event_inference_but_keep_valid_tcp_hits(self):
  c=attach_phases(self.capture(clean_recording(timeline(2),T0,T9),hit()));self.assertEqual(c['event_evidence']['events'][0]['phase_context']['stages'],[]);self.assertEqual(c['endpoints'][0]['phase_context']['stages'],['launch']);self.assertFalse(c['endpoints'][0]['phase_context']['association_complete'])
 def test_legacy_no_phase_assignment_even_with_stray_hits(self):
  c=attach_phases(self.capture(hits=hit()));self.assertEqual(c['endpoints'][0]['phase_context']['stages'],[])

class RevisionBackend(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 export=analysis_tests.AnalysisTests.export
 def capture(self,ident='a'*32,rows=None,events=None,phase=None,start=T0,end=T9):
  self.m.collector=lambda p,j:dict(seconds=60,query_errors=0,capture_started_utc=start,capture_ended_utc=end,phase_recording=phase or timeline(),endpoints=rows if rows is not None else [endpoint(phase_hits=hit())],event_evidence=dict(events=events or []))
  return self.m.run('observe',dict(program=str(self.exe),seconds=60),ident)['observation']
 def test_plan_fixed_phase_path_and_persistence(self):
  plans=[];self.m.collector=lambda p,j:(plans.append(p) or dict(endpoints=[]));self.m.run('observe',dict(program=str(self.exe),seconds=60),'a'*32);self.assertEqual(plans[0]['phase_path'],str(self.m.private/('job-'+'a'*32+'.phase.json')))
  c=self.capture();self.assertEqual(c['endpoints'][0]['phase_context']['stages'],['launch']);self.assertEqual(self.m.captures.read(c['capture_id'])['phase_recording']['status'],'available')
 def test_manual_and_sample_phase_separate_and_history_has_provenance(self):
  a=self.capture();self.m.captures.save_annotations(a['capture_id'],{a['endpoints'][0]['record_id']:['in_game']});a=self.m.captures.read(a['capture_id']);self.assertEqual(a['endpoints'][0]['context']['stages'],['in_game']);self.assertEqual(a['endpoints'][0]['phase_context']['stages'],['launch'])
  b=self.capture('b'*32,phase={'schema':'wow-stage-recording-1','transitions':[]});ctx=b['endpoints'][0]['context'];self.assertEqual(ctx['stages'],[]);self.assertEqual(ctx['history_stages'],['launch','in_game']);self.assertEqual(ctx['history_sources'][0]['manual_stages'],['in_game']);self.assertEqual(ctx['history_sources'][0]['session_stages'],['launch'])
 def test_repeated_key_history_merges_source_types(self):
  a=self.capture(rows=[endpoint(phase_hits=hit()),{**endpoint(phase_hits=hit('login',T2,T2)),'pid':13}]);self.m.captures.save_annotations(a['capture_id'],{a['endpoints'][1]['record_id']:['in_game']});b=self.capture('b'*32);src=b['endpoints'][0]['context']['history_sources'][0];self.assertEqual(src['session_stages'],['launch','login']);self.assertEqual(src['manual_stages'],['in_game'])
 def test_compare_ignores_pid_but_not_port_and_does_not_use_inherited_labels(self):
  a=self.capture();self.m.captures.save_annotations(a['capture_id'],{a['endpoints'][0]['record_id']:['in_game']});b=self.capture('b'*32,rows=[{**endpoint(phase_hits=hit()),'pid':99},{**endpoint(),'port':443}]);r=compare([self.m.captures.read(a['capture_id']),b]);tcp=r['changes']['tcp'];self.assertEqual(len(tcp['shared']),1);self.assertEqual(tcp['shared'][0]['compared']['manual_stages'],[]);self.assertEqual(tcp['added'][0]['port'],443);self.assertFalse(r['block_success_verified'])
 def test_protocol_and_dns_wfp_separate(self):
  a=self.capture(events=[dns(),block()]);b=self.capture('b'*32,events=[{**dns(),'domain':'other.example'}]);r=compare([a,b]);self.assertEqual(len(r['changes']['dns']['added']),1);self.assertEqual(len(r['changes']['wfp']['not_seen_again']),1);self.assertEqual(len(r['changes']['tcp']['shared']),1)
  c=copy.deepcopy(a);c['event_evidence']['events'][1]['protocol']='UDP';self.assertNotEqual(set(group_rows(a,'wfp')),set(group_rows(c,'wfp')))
 def test_reverse_selection_order_and_duration_warning(self):
  a=self.capture();b=self.capture('b'*32,start='2026-01-02T00:00:00Z',end='2026-01-02T00:01:00Z',phase={'schema':'wow-stage-recording-1','transitions':[]});b['seconds']=120;r=compare([b,a]);self.assertEqual(r['baseline']['capture_id'],a['capture_id']);self.assertIn('مدت ضبط', ' '.join(r['warnings']))
 def test_invalid_selection_rejected(self):
  self.capture()
  for ids in ([],['a'*32],['a'*32]*2,['a'*32,'b'*32,'c'*32]):
   with self.assertRaises(BlacklistError):self.m.run('compare_captures',dict(capture_ids=ids))
 def test_compare_read_only_without_owner_or_game(self):
  self.capture();self.capture('b'*32);self.calls.clear();self.exe.unlink()
  with patch('socket.gethostbyaddr',side_effect=AssertionError('network')):
   r=self.m.run('compare_captures',dict(capture_ids=['a'*32,'b'*32]))
  self.assertEqual(self.calls,[]);self.assertIn('comparison_text',r);self.assertIn('ندیدن دوباره',r['comparison_text'])
 def test_deleted_rows_excluded_and_warning(self):
  a=self.capture();b=self.capture('b'*32);self.m.run('delete_records',dict(capture_id=b['capture_id'],record_ids=[b['endpoints'][0]['record_id']],deletion_consent=True));r=compare([a,self.m.captures.read(b['capture_id'])]);self.assertEqual(len(r['changes']['tcp']['not_seen_again']),1);self.assertIn('حذف صریح',' '.join(r['warnings']))
 def test_two_export_adds_comparison_and_separate_phases(self):
  a=self.capture();self.capture('b'*32);_,report,files=self.export(ids=['a'*32,'b'*32],annotations=dict(capture_id=a['capture_id'],entries={a['endpoints'][0]['record_id']:['login']}));self.assertIn('comparison.json',files);self.assertIn('comparison.fa.txt',files);self.assertEqual(json.loads(files['comparison.json'])['schema'],'wow-capture-comparison-1');row=report['captures'][0]['endpoints'][0];self.assertEqual(row['phase_context']['stages'],['launch']);self.assertEqual(row['context']['stages'],['login']);self.assertIn('مرحله‌های نمونه‌برداری تحت انتخاب کاربر',files['report.fa.txt'].decode())
 def test_single_export_unchanged_names(self):
  self.capture();_,_,files=self.export();self.assertNotIn('comparison.json',files)
 def test_missing_rule_and_phase_coverage_warning(self):
  a=self.capture();b=copy.deepcopy(a);b['capture_id']='b'*32;b['phase_recording']=clean_recording(None);b['block_snapshot']={'available':False};b['truncated']=True;b['program_sha256']='f'*64;r=compare([a,b]);self.assertFalse(r['rule_configuration_changes']['available']);self.assertIn('hash',' '.join(r['warnings']));self.assertIn('مرحله',' '.join(r['warnings']))

@unittest.skipUnless(PS,'PowerShell QA runtime required')
class RevisionPowerShell(unittest.TestCase):
 def runps(self,code):
  bootstrap="$ErrorActionPreference='Stop';$root='"+quoted(BASE)+"';function Import-Functions($path){$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$e);if($e.Count){throw 'parse_error'};foreach($n in $ast.EndBlock.Statements){if($n -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create(($n.Extent.Text -replace '^function\\s+', 'function script:')))}}};foreach($name in @('ui-analysis.ps1','ui-live-model.ps1','ui-session.ps1')){Import-Functions (Join-Path $root ('app/'+$name))};"
  p=subprocess.run([PS,'-NoProfile','-NonInteractive','-Command',bootstrap+code+';exit 0'],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1','WOW_BL_APP':str(BASE/'app')},capture_output=True,timeout=30);self.assertEqual(p.returncode,0,(p.stdout+p.stderr).decode(errors='replace')[:6000]);return p.stdout.decode('utf-8-sig')
 def test_health_counts_pause_stale_and_errors(self):
  self.runps("$script:stageLabels=@{unknown='نامشخص';launch='لانچ'};$script:sessionStage='launch';$script:sessionTransitions=@();$script:liveRunning=$true;$script:liveLastArrival=[DateTime]::UtcNow;$script:livePause=[pscustomobject]@{Checked=$true};$script:liveLastSnapshot=('{\"sampled_utc\":\"2026-01-01T00:00:00Z\",\"endpoints\":[{},{}],\"event_evidence\":{\"events\":[{\"kind\":\"dns_query\"},{\"kind\":\"wfp_connection_block\"}],\"streams\":{}},\"phase_recording\":{\"read_errors\":1}}'|ConvertFrom-Json);$t=Recorder-HealthText;if($t -notmatch 'TCP 2' -or $t -notmatch 'DNS 1' -or $t -notmatch 'منع WFP 1' -or $t -notmatch 'دریافت/ضبط ادامه دارد' -or $t -notmatch 'خطای خواندن مرحله'){throw $t};$script:liveLastArrival=[DateTime]::UtcNow.AddSeconds(-8);if((Recorder-HealthText) -notmatch '۴ ثانیه'){throw 'stale'}")
 def test_health_preparing_stopping_and_failed(self):
  self.runps("$script:liveRunning=$true;$script:liveLastSnapshot=$null;if((Recorder-HealthText) -notmatch 'آماده‌سازی'){throw 'preparing'};$script:recordingStopping=$true;if((Recorder-HealthText) -notmatch 'در حال پایان'){throw 'stopping'};$script:liveRunning=$false;$script:liveFailed=$true;if((Recorder-HealthText) -notmatch 'تأیید نشد'){throw 'failed'}")
 def test_selector_commits_atomic_journal_and_rejects_stop_changes(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'phase.json';code="$script:sessionCodes=@('unknown','launch','login','dashboard','in_game');$script:liveCaptureId='"+'a'*32+"';$script:liveJob=@{Phases='"+quoted(p)+"'};$script:liveRunning=$true;$script:sessionSelector=[pscustomobject]@{SelectedIndex=0};function Write-UiDiagnostic{};function Update-RecorderHealth{};Start-SessionStages;Select-SessionStage 'launch';Select-SessionStage 'login';$saved=Get-Content $script:liveJob.Phases -Raw|ConvertFrom-Json;if($saved.transitions.Count -ne 3 -or $saved.transitions[2].stage -ne 'login'){throw 'atomic_journal'};$script:recordingStopping=$true;Select-SessionStage 'in_game';if($script:sessionTransitions.Count -ne 3){throw 'changed_after_stop'}"
   self.runps(code)
 def test_selector_failed_write_preserves_prior_stage(self):
  self.runps("$script:sessionCodes=@('unknown','launch','login','dashboard','in_game');$script:liveRunning=$true;$script:sessionStage='launch';$script:sessionTransitions=@([pscustomobject]@{sequence=1;stage='launch';selected_utc=[DateTime]::UtcNow.AddSeconds(-1).ToString('o')});$script:sessionSelector=[pscustomobject]@{SelectedIndex=2};$status=[pscustomobject]@{Text=''};function Publish-StageTimeline($e){return $false};function Update-RecorderHealth{};Select-SessionStage 'login';if($script:sessionStage -ne 'launch' -or $script:sessionTransitions.Count -ne 1 -or $script:sessionSelector.SelectedIndex -ne 1){throw 'failed_write_committed'}")
 def test_journal_ps_dates_append_only_invalid_becomes_unknown(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'phase.json';code="$start=[DateTime]::UtcNow;$j=@{phase_path='"+quoted(p)+"';capture_id='"+'a'*32+"'};. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/observe-phase.ps1'))));$entries=@([pscustomobject]@{sequence=1;stage='launch';selected_utc=$start.AddSeconds(-1).ToString('o')});function Write-J {param($e) [IO.File]::WriteAllText($j.phase_path,(@{schema='wow-stage-journal-1';capture_id=$j.capture_id;transitions=@($e)}|ConvertTo-Json -Depth 6));$script:phaseLastStamp=[DateTime]::MinValue};Write-J $entries;Read-StageJournal;if((Stage-AtSample ([DateTime]::UtcNow)) -ne 'launch'){throw 'PS_date_parse'};$entries+=@([pscustomobject]@{sequence=2;stage='login';selected_utc=[DateTime]::UtcNow.ToString('o')});Write-J $entries;Read-StageJournal;if((Stage-AtSample ([DateTime]::UtcNow)) -ne 'login'){throw 'append'};$entries[0].stage='dashboard';Write-J $entries;Read-StageJournal;if(!$script:phaseReadErrors -or (Stage-AtSample ([DateTime]::UtcNow)) -ne 'unknown'){throw 'invalid_not_unknown'};if($script:phaseTransitions[0].stage -ne 'launch'){throw 'prefix_mutated'}"
   self.runps(code)
 def test_live_event_uses_original_time_and_refuses_journal_errors(self):
  self.runps("$script:stageLabels=@{unknown='نامشخص';launch='لانچ';login='ورود'};$script:liveLastSnapshot=('{\"capture_started_utc\":\"2026-01-01T00:00:00Z\",\"published_utc\":\"2026-01-01T00:01:00Z\",\"phase_recording\":{\"transitions\":[{\"sequence\":1,\"stage\":\"launch\",\"selected_utc\":\"2026-01-01T00:00:00Z\"},{\"sequence\":2,\"stage\":\"login\",\"selected_utc\":\"2026-01-01T00:00:10Z\"}],\"read_errors\":0}}'|ConvertFrom-Json);$r=[pscustomobject]@{observed_utc='2026-01-01T00:00:02Z'};if((@(Live-EventSessionStages $r) -join ',') -ne 'launch'){throw 'event_arrival_not_original_time'};$script:liveLastSnapshot.phase_recording.read_errors=1;if(@(Live-EventSessionStages $r).Count){throw 'errors_not_unknown'}")
 def test_actual_collector_three_phases_absent_endpoint_not_relabelled(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);exe=r/'Wow.exe';exe.write_bytes(b'fixture');plan=dict(program=str(exe),program_sha256=digest(exe),seconds=0,parent_pid=os.getpid(),capture_id='a'*32,ready_path=str(r/'ready'),stop_path=str(r/'stop'),phase_path=str(r/'phases'),live_path=str(r/'live'),history_baseline=dict(keys=[],complete=True),public_exclusions_v4=[],public_exclusions_v6=[]);(r/'plan').write_text(json.dumps(plan))
   code="$env:WOW_BL_REQUEST='"+quoted(r/'plan')+"';$global:mockPlan=Get-Content $env:WOW_BL_REQUEST -Raw|ConvertFrom-Json;$global:entries=@([pscustomobject]@{sequence=1;stage='launch';selected_utc=[DateTime]::UtcNow.AddSeconds(-1).ToString('o')});function Write-J {[IO.File]::WriteAllText($global:mockPlan.phase_path,(@{schema='wow-stage-journal-1';capture_id=$global:mockPlan.capture_id;transitions=@($global:entries)}|ConvertTo-Json -Depth 6))};Write-J;$global:tick=0;$global:born=[DateTime]::Now;function Get-Process {param($Id,$Name,$ErrorAction);[pscustomobject]@{Id=123;Path=$global:mockPlan.program;StartTime=$global:born}};function Get-NetTCPConnection {$global:tick++;[pscustomobject]@{OwningProcess=123;RemoteAddress='2.19.198.11';RemotePort=80;State='Established'};if($global:tick -eq 1){[pscustomobject]@{OwningProcess=123;RemoteAddress='3.125.189.135';RemotePort=443;State='SynSent'}}};function Start-Sleep {param($Milliseconds);if($global:tick -lt 3){$global:entries+=@([pscustomobject]@{sequence=($global:entries.Count+1);stage=$(if($global:tick -eq 1){'login'}else{'in_game'});selected_utc=[DateTime]::UtcNow.ToString('o')});Write-J}else{[IO.File]::WriteAllText($global:mockPlan.stop_path,'stop')}};& ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/observe.ps1'))))"
   result=json.loads(self.runps(code));self.assertTrue(result['ok']);self.assertTrue(result['endpoints'],str(result));self.assertEqual(result['query_errors'],0);rows={x['ip']:x for x in result['endpoints']};self.assertEqual(set(rows['2.19.198.11']['phase_hits']),{'launch','login','in_game'});self.assertEqual(set(rows['3.125.189.135']['phase_hits']),{'launch'});self.assertEqual(result['phase_recording']['read_errors'],0);frame=json.loads((r/'live').read_text());self.assertTrue(frame['finished']);self.assertTrue(frame['sampled_utc'])

class SimpleUIContract(unittest.TestCase):
 def test_options_menu_and_no_new_tabs(self):
  live=(BASE/'app/ui-live.ps1').read_text();self.assertIn('ContextMenuStrip',live);self.assertIn('New-SessionSelector',live);self.assertEqual(live.count('liveTabs.TabPages.Add('),2)
 def test_compare_readonly_before_owner_and_exact_two(self):
  source=(BASE/'app/backend.py').read_text();self.assertLess(source.index("if action=='compare_captures'"),source.index("self.owner(create=",source.index("if action=='compare_captures'")));self.assertIn('len(ids)!=2',source)
