"""Regression tests for user-requested hosts, stages, lifecycle, PTR and record deletion."""
import contextlib,hashlib,json,os,stat,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,BlacklistError,atomic
from capture_store import stage_codes,stage_identity
from hosts_edit import prepare,apply_hosts
from hosts_view import parse_hosts
import hosts_view,hosts_edit,test_manager as tm
import test_analysis_export as analysis_tests
from test_event_evidence import dns,block
from test_real_powershell import PS,quoted

class RevisionBackend(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 capture=analysis_tests.AnalysisTests.capture
 export=analysis_tests.AnalysisTests.export
 def tag(self,c,codes):
  key=c['endpoints'][0]['record_id'];return self.m.captures.save_annotations(c['capture_id'],{key:codes})
 def test_multiple_stages_deduplicated_ordered_and_persisted(self):
  c=self.capture();self.tag(c,['login','launch','login','dashboard']);row=self.m.captures.read(c['capture_id'])['endpoints'][0]
  self.assertEqual(row['context']['stages'],['launch','login','dashboard']);self.assertEqual(row['context']['stage'],'multi_stage');self.assertEqual(row['context']['history_stages'],[])
 def test_stage_array_validation(self):
  c=self.capture();key=c['endpoints'][0]['record_id']
  for code in (None,5,{},['fake'],['login',[]],['login']*31):
   with self.assertRaises(ValueError):self.m.captures.save_annotations(c['capture_id'],{key:code})
 def test_old_single_stage_migrates_without_rewriting_raw_or_old_sidecar(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];p=self.m.captures.annotation_path(c['capture_id']);p.parent.mkdir(exist_ok=True)
  atomic(p,dict(schema='wow-capture-annotations-1',capture_id=c['capture_id'],entries={key:dict(stage='login',annotated_utc='2026-01-01T00:00:00Z')}));before=p.read_bytes()
  row=self.m.captures.read(c['capture_id'])['endpoints'][0];self.assertEqual(row['context']['stages'],['login']);self.assertEqual(p.read_bytes(),before)
 def test_next_capture_recovers_labels_without_falsely_annotating_current_stage(self):
  a=self.capture();self.tag(a,['launch','login']);b=self.capture('b'*32);row=b['endpoints'][0]
  self.assertEqual(row['context']['stage'],'unknown');self.assertEqual(row['context']['stages'],[]);self.assertEqual(row['context']['history_stages'],['launch','login']);self.assertEqual(row['context']['effective_stages'],['launch','login']);self.assertEqual(row['context']['source'],'previous_captures_only');self.assertEqual(row['context']['history_sources'][0]['capture_id'],a['capture_id'])
 def test_history_and_current_phases_remain_distinct_in_export(self):
  a=self.capture();self.tag(a,['launch','login']);b=self.capture('b'*32);self.tag(b,['in_game']);_,r,files=self.export(ids=[b['capture_id']]);ctx=r['captures'][0]['endpoints'][0]['context']
  self.assertEqual(ctx['stages'],['in_game']);self.assertEqual(ctx['history_stages'],['launch','login']);self.assertIn('سابقه ضبط‌های دیگر',files['report.fa.txt'].decode());self.assertFalse(ctx['event_time_verified'])
 def test_pending_export_labels_project_into_other_selected_captures(self):
  a=self.capture();b=self.capture('b'*32);key=a['endpoints'][0]['record_id'];_,report,_=self.export(ids=[a['capture_id'],b['capture_id']],annotations=dict(capture_id=a['capture_id'],entries={key:['launch','login']}))
  self.assertEqual(report['captures'][1]['endpoints'][0]['context']['history_stages'],['launch','login']);self.assertEqual(report['captures'][1]['endpoints'][0]['context']['stages'],[])
 def test_history_phase_union_includes_sources_beyond_visible_provenance_limit(self):
  a=self.capture();self.tag(a,['in_game'])
  for i in range(1,22):
   c=self.capture(format(i,'032x'));self.tag(c,['login'])
  latest=self.capture('f'*32);ctx=latest['endpoints'][0]['context'];self.assertEqual(ctx['history_stages'],['login','in_game']);self.assertGreater(ctx['history_source_count'],20);self.assertEqual(len(ctx['history_sources']),20);self.assertTrue(ctx['history_sources_truncated'])
 def test_different_port_does_not_inherit_labels(self):
  a=self.capture();self.tag(a,['login']);b=self.capture('b'*32,rows=[{**a['endpoints'][0],'port':443}]);self.assertEqual(b['endpoints'][0]['context']['history_stages'],[])
 def test_current_unknown_clear_does_not_erase_other_capture_history(self):
  a=self.capture();self.tag(a,['login']);b=self.capture('b'*32);self.tag(b,['dashboard']);self.tag(b,[]);ctx=self.m.captures.read(b['capture_id'])['endpoints'][0]['context'];self.assertEqual(ctx['stages'],[]);self.assertEqual(ctx['history_stages'],['login'])
 def test_unchanged_multiple_stages_keep_timestamp(self):
  c=self.capture();self.tag(c,['login','launch']);before=self.m.captures.annotations(c['capture_id']);self.assertEqual(self.tag(c,['launch','login'])['changed'],0);self.assertEqual(before,self.m.captures.annotations(c['capture_id']))
 def evidence_capture(self,ident):
  self.m.collector=lambda p,j:dict(endpoints=[],event_evidence=dict(events=[dns(),block()]))
  return self.m.run('observe',dict(program=str(self.exe),seconds=60),ident)['observation']
 def test_dns_and_wfp_stage_history_exact_targets(self):
  self.evidence_capture('a'*32);self.m.captures.save_annotations('a'*32,{'c'*32:['login','in_game'],'d'*32:['launch']});b=self.evidence_capture('b'*32)
  self.assertEqual(b['event_evidence']['events'][0]['context']['history_stages'],['login','in_game']);self.assertEqual(b['event_evidence']['events'][1]['context']['history_stages'],['launch']);self.assertNotEqual(stage_identity(dns()),stage_identity(block()))
 def test_live_plan_carries_bounded_stage_baseline(self):
  c=self.capture();self.tag(c,['login','in_game']);plans=[];self.m.collector=lambda p,j:(plans.append(p) or dict(endpoints=[]));self.m.run('observe',dict(program=str(self.exe),seconds=60),'b'*32)
  self.assertEqual(set(plans[0]['stage_baseline']['2.19.198.11|80|TCP']),{'login','in_game'})
 def test_record_delete_requires_consent_and_valid_target(self):
  c=self.capture();key=c['endpoints'][0]['record_id']
  for data in (dict(record_ids=[key]),dict(record_ids=['../bad'],deletion_consent=True)):
   with self.assertRaises(BlacklistError):self.m.run('delete_records',dict(capture_id=c['capture_id'],**data))
  self.assertEqual(len(self.m.captures.read(c['capture_id'])['endpoints']),1)
 def test_delete_rows_filters_export_and_history_without_changing_raw_or_rules(self):
  c=self.capture();self.tag(c,['login']);key=c['endpoints'][0]['record_id'];raw=self.m.captures.capture_path(c['capture_id']).read_bytes();txt=self.m.text_path.read_bytes();self.calls.clear()
  result=self.m.run('delete_records',dict(capture_id=c['capture_id'],record_ids=[key],deletion_consent=True));self.assertEqual(result['observation']['endpoints'],[]);self.assertEqual(self.calls,[]);self.assertEqual(raw,self.m.captures.capture_path(c['capture_id']).read_bytes());self.assertEqual(txt,self.m.text_path.read_bytes());self.assertEqual(self.m.captures.history()['entries'][0]['records'],0)
  result,report,_=self.export();self.assertEqual(result['record_count'],0);self.assertEqual(report['captures'][0]['deleted_record_count'],1);self.assertEqual(report['captures'][0]['endpoints'],[])
 def test_deleted_labels_do_not_inherit_into_new_capture(self):
  c=self.capture();self.tag(c,['login']);self.m.captures.delete_records(c['capture_id'],[c['endpoints'][0]['record_id']],True);b=self.capture('b'*32);self.assertEqual(b['endpoints'][0]['context']['history_stages'],[])
 def test_delete_event_rows_without_tcp_and_keep_other_event(self):
  c=self.evidence_capture('a'*32);self.m.captures.delete_records(c['capture_id'],['c'*32],True);r=self.m.captures.read(c['capture_id']);self.assertEqual([x['record_id'] for x in r['event_evidence']['events']],['d'*32])
 def test_live_journal_recovers_deletions_and_multiple_phases(self):
  def collect(p,j):
   atomic(self.m.private/('job-'+j+'.live-labels.json'),dict(schema='wow-live-labels-1',capture_id=j,entries={'c'*32:['login','in_game'],'d'*32:['launch']},deleted_record_ids=['c'*32]));return dict(endpoints=[],event_evidence=dict(events=[dns(),block()]))
  self.m.collector=collect;r=self.m.run('observe',dict(program=str(self.exe),seconds=60),'a'*32)['observation'];self.assertEqual(r['live_annotation_recovery']['state'],'saved');self.assertEqual(r['deleted_record_count'],1);self.assertEqual(r['event_evidence']['events'][0]['context']['stages'],['launch'])
 def test_capture_delete_moves_only_capture_and_sidecars(self):
  c=self.capture();self.tag(c,['login']);self.m.captures.delete_records(c['capture_id'],[c['endpoints'][0]['record_id']],True);self.calls.clear();config=self.m.config_path.read_bytes()
  result=self.m.run('delete_captures',dict(capture_ids=[c['capture_id']],deletion_consent=True));self.assertEqual(result['history']['entries'],[]);trash=self.m.private/'deleted-captures'/c['capture_id'];self.assertTrue((trash/('destinations-'+c['capture_id']+'.json')).exists());self.assertTrue((trash/'capture-annotations'/(c['capture_id']+'.json')).exists());self.assertEqual(self.calls,[]);self.assertEqual(self.m.config_path.read_bytes(),config)
  with self.assertRaises(BlacklistError):self.m.run('load_observation',dict(capture_id=c['capture_id']))
 def test_bulk_capture_delete_validates_all_before_moves(self):
  c=self.capture()
  for ids in ([c['capture_id'],'b'*32],[c['capture_id'],'../bad'],[c['capture_id']]*2):
   with self.assertRaises(BlacklistError):self.m.run('delete_captures',dict(capture_ids=ids,deletion_consent=True))
   self.assertTrue(self.m.captures.capture_path(c['capture_id']).exists())
 def test_failed_bulk_move_rolls_back_and_can_retry(self):
  a=self.capture();b=self.capture('b'*32);real=Path.rename
  def rename(path,target):
   if path==self.m.captures.capture_path(b['capture_id']):raise OSError('injected')
   return real(path,target)
  with patch.object(Path,'rename',rename):
   with self.assertRaises(OSError):self.m.captures.delete_captures([a['capture_id'],b['capture_id']],True)
  self.assertTrue(self.m.captures.capture_path(a['capture_id']).exists());self.assertTrue(self.m.captures.capture_path(b['capture_id']).exists());self.assertEqual(self.m.captures.delete_captures([a['capture_id'],b['capture_id']],True)['deleted'],2)
 def test_capture_delete_denied_without_consent(self):
  c=self.capture()
  with self.assertRaises(BlacklistError):self.m.run('delete_captures',dict(capture_ids=[c['capture_id']]))
 def test_corrupt_deletion_index_fails_closed_does_not_reexpose_rows(self):
  c=self.capture();p=self.m.captures.deletion_path(c['capture_id']);p.parent.mkdir();p.write_text('invalid')
  with self.assertRaises(BlacklistError):self.m.run('load_observation',dict(capture_id=c['capture_id']))
 def test_hosts_edit_requires_explicit_system_wide_consent_without_firewall(self):
  self.calls.clear()
  with self.assertRaises(BlacklistError):self.m.run('hosts_apply',{})
  self.assertEqual(self.calls,[])

class HostsEditTests(unittest.TestCase):
 def test_remove_alias_preserves_other_alias_and_comments(self):
  data=b'# keep\r\n0.0.0.0 a.example  b.example\t# note\r\n127.0.0.1 localhost\r\ninvalid keep\r\n'
  out,_=prepare(data,[dict(action='remove',domain='a.example')]);self.assertIn(b'b.example\t# note\r\n',out);self.assertIn(b'# keep\r\n',out);self.assertIn(b'invalid keep\r\n',out);self.assertIn(b'127.0.0.1 localhost\r\n',out);self.assertNotIn(b'a.example',out)
 def test_remove_entire_alias_line_keeps_comment(self):
  out,_=prepare(b'0.0.0.0 a.example # keep comment\r\n',[dict(action='remove',domain='a.example')]);self.assertIn(b'# keep comment\r\n',out);self.assertEqual(parse_hosts(out)['entries'],[])
 def test_edit_replaces_all_domain_mappings_without_other_aliases(self):
  out,_=prepare(b'0.0.0.0 a.example b.example\n:: a.example\n',[dict(action='upsert',domain='a.example',addresses=['127.0.0.1','::1'])]);rows={r['domain']:r['addresses'] for r in parse_hosts(out)['entries']};self.assertEqual(rows['a.example'],['127.0.0.1','::1']);self.assertEqual(rows['b.example'],['0.0.0.0'])
 def test_encodings_and_newline_preserved(self):
  for encoding,bom in [('utf-8',b''),('utf-8',b'\xef\xbb\xbf'),('utf-16-le',b'\xff\xfe'),('utf-16-be',b'\xfe\xff'),('cp1252',b'')]:
   text='# caf\xe9\r\n0.0.0.0 a.example\r\n';out,_=prepare(bom+text.encode(encoding),[dict(action='upsert',domain='b.example',addresses=['::'])]);self.assertTrue(out.startswith(bom+text.encode(encoding)));self.assertIn('::\tb.example\r\n',out[len(bom):].decode(encoding))
 def test_reject_injection_system_names_and_invalid_values(self):
  for domain,addresses in [('a.example\nother', ['0.0.0.0']),('localhost',['0.0.0.0']),('https://a.example',['0.0.0.0']),('a.example',['1.2.3.4 # injected']),('a.example',[1]),('a.example',[])]:
   with self.assertRaises(ValueError):prepare(b'',[dict(action='upsert',domain=domain,addresses=addresses)])
 def test_unicode_domain_idna_and_ipv6(self):
  out,_=prepare(b'',[dict(action='upsert',domain='m\xfcnich.example',addresses=['2001:db8::1'])]);self.assertEqual(parse_hosts(out)['entries'][0]['domain'],'xn--mnich-kva.example')
 def fixture(self,root,data):
  path=Path(root)/'Windows/System32/drivers/etc/hosts';path.parent.mkdir(parents=True);path.write_bytes(data);private=Path(root)/'private';private.mkdir();return path,private,dict(expected_sha256=hashlib.sha256(data).hexdigest(),hosts_edit_consent=True,changes=[dict(action='upsert',domain='b.example',addresses=['0.0.0.0'])])
 def test_locked_apply_backup_and_same_inode_permissions(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'# original\r\n0.0.0.0 a.example\r\n');path.chmod(0o640);before=path.stat()
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):result=apply_hosts(private,payload)
   self.assertTrue(result['changed']);self.assertEqual((private/'hosts-backups'/result['backup_filename']).read_bytes(),b'# original\r\n0.0.0.0 a.example\r\n');self.assertEqual(before.st_ino,path.stat().st_ino);self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o640);self.assertFalse(result['dns_cache_flushed']);self.assertFalse(result['blocking_verified'])
 def test_external_change_refuses_write_without_backup(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'');path.write_bytes(b'# external')
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):
    with self.assertRaisesRegex(ValueError,'changed_externally'):apply_hosts(private,payload)
   self.assertEqual(path.read_bytes(),b'# external');self.assertFalse((private/'hosts-backups').exists())
 def test_exclusive_lock_refuses_second_writer(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'')
   with hosts_edit.locked_file(path),patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):
    with self.assertRaises(OSError):apply_hosts(private,payload)
   self.assertEqual(path.read_bytes(),b'')
 def test_reparse_and_hardlink_refused(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'');target=Path(t)/'other';target.write_bytes(b'');path.unlink();path.symlink_to(target)
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):
    with self.assertRaises(ValueError):apply_hosts(private,payload)
   path.unlink();os.link(target,path)
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):
    with self.assertRaises(ValueError):apply_hosts(private,payload)
 def test_backup_failure_keeps_original(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'# original');(private/'hosts-backups').write_text('not a folder')
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}):
    with self.assertRaises(OSError):apply_hosts(private,payload)
   self.assertEqual(path.read_bytes(),b'# original')
 def test_write_failure_rolls_back_under_lock(self):
  with tempfile.TemporaryDirectory() as t:
   path,private,payload=self.fixture(t,b'# original');real=hosts_edit.locked_file
   class Failure:
    def __init__(self,f):self.f=f;self.failed=False
    def __getattr__(self,k):return getattr(self.f,k)
    def write(self,b):
     if not self.failed:self.failed=True;self.f.write(b[:3]);raise OSError('injected write failure')
     return self.f.write(b)
   @contextlib.contextmanager
   def locked(p):
    with real(p) as f:yield Failure(f)
   with patch.object(hosts_view,'IS_WINDOWS',True),patch.dict(os.environ,{'SystemRoot':str(Path(t)/'Windows')}),patch.object(hosts_edit,'locked_file',locked):
    with self.assertRaisesRegex(ValueError,'original_restored'):apply_hosts(private,payload)
   self.assertEqual(path.read_bytes(),b'# original');self.assertEqual(len(list((private/'hosts-backups').glob('*.bak'))),1)

@unittest.skipUnless(PS,'QA PowerShell required')
class RevisionPowerShell(unittest.TestCase):
 def runps(self,code):
  bootstrap="$ErrorActionPreference='Stop';$root='"+quoted(BASE)+"';function Import-Functions($path){$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$e);if($e.Count){throw 'parse_error'};foreach($n in $ast.EndBlock.Statements){if($n -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($n.Extent.Text))}}};"
  # Preserve the function signature as well as the body (Ast.Body alone loses parameters).
  bootstrap=bootstrap.replace('. ([scriptblock]::Create($n.Extent.Text))', ". ([scriptblock]::Create(($n.Extent.Text -replace '^function\\s+', 'function script:')))")
  bootstrap+="foreach($name in @('ui-analysis.ps1','ui-live.ps1','ui-tools.ps1')){Import-Functions (Join-Path $root ('app/'+$name))};"
  r=subprocess.run([PS,'-NoProfile','-NonInteractive','-Command',bootstrap+code+';exit 0'],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1'},capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stdout.decode()+r.stderr.decode());return r.stdout.decode()
 def test_multiple_stage_labels_and_explicit_vs_inherited_live(self):
  self.runps("$script:stageLabels=@{unknown='نامشخص';launch='لانچ';login='ورود';dashboard='داشبورد';in_game='بازی';multi_stage='چند مرحله'};$script:stageEdits=@{};$script:liveStages=@{};function Observation-Key($r){return $r.record_id};$r=[pscustomobject]@{record_id='a';ip='2.19.198.11';port=80;context=[pscustomobject]@{stages=@('login','in_game');history_stages=@('launch')}};$script:stageEdits.a=@('login','in_game');$text=Stage-For $r;if($text -notmatch 'ورود، بازی' -or $text -notmatch 'سابقه: لانچ'){throw 'main_stages'};$script:liveStages.a=@('dashboard');$text=Live-StageText $r;if($text -notmatch 'این ضبط: داشبورد' -or $text -notmatch 'سابقه: لانچ'){throw 'live_stages'}")
 def test_live_stage_baseline_does_not_mark_current_stage(self):
  self.runps("$script:stageLabels=@{unknown='نامشخص';login='ورود'};$script:liveStages=@{};$script:liveLastSnapshot=('{\"stage_baseline\":{\"2.19.198.11|80|TCP\":[\"login\"]}}'|ConvertFrom-Json);$r=[pscustomobject]@{record_id='a';ip='2.19.198.11';port=80};$text=Live-StageText $r;if($text -ne 'این ضبط: نامشخص | سابقه: ورود'){throw $text}")
 def test_stop_both_sources_use_one_state_and_preserve_main_job(self):
  with tempfile.TemporaryDirectory() as t:
   stop=Path(t)/'stop';code="$script:job=@{Action='observe';Stop='"+quoted(stop)+"'};$script:ptrJob=$null;$script:liveSummary=[pscustomobject]@{Text=''};$stop=[pscustomobject]@{Enabled=$true};$status=[pscustomobject]@{Text=''};function Commit-ObservationEdits{};function Save-LiveLabels{$script:flushed=$true};function Set-LiveBusy{$script:popupStopDisabled=$script:recordingStopping};Request-RecordingStop;if(!$script:flushed -or !$script:recordingStopping -or $stop.Enabled -or !$script:popupStopDisabled -or $script:job.Action -ne 'observe'){throw 'stop_state'}"
   self.runps(code);self.assertTrue(stop.exists())
 def test_accept_canonical_data_even_if_main_render_throws(self):
  self.runps("$script:observed=@();$report=[pscustomobject]@{endpoints=@([pscustomobject]@{ip='2.19.198.11'});block_snapshot='snapshot'};$onlyFresh=[pscustomobject]@{Checked=$true};$hideCovered=[pscustomobject]@{Checked=$true};function Set-CaptureContext($r,$h){$script:captureId='saved'};function Show-ObservedRows{throw 'render_fault'};try{Accept-CaptureReport $report $false}catch{};if($script:observed.Count -ne 1 -or $script:observationSnapshot -ne 'snapshot' -or $script:captureId -ne 'saved' -or $onlyFresh.Checked -or $hideCovered.Checked){throw 'model_not_preserved'}")
 def test_final_snapshot_uses_report_not_stale_progress(self):
  self.runps("$script:liveForm=$null;$script:liveRunning=$true;$script:liveStages=@{};$script:stageEdits=@{};$script:liveLastSnapshot=[pscustomobject]@{endpoints=@('stale')};function Update-AnnotationIndicator{};function Set-LiveBusy{};$r=[pscustomobject]@{endpoints=@([pscustomobject]@{record_id='a';ip='2.19.198.11'});event_evidence=[pscustomobject]@{events=@()};seconds=5};Finish-LiveCapture $r;if($script:liveRunning -or $script:liveLastSnapshot.endpoints[0].ip -ne '2.19.198.11'){throw 'stale_final'}")
 def test_late_deletion_and_stage_edits_queue_until_ptr_finishes(self):
  self.runps("$script:liveDeleted=@{a=$true};$script:captureId='capture';$script:annotationsDirty=$true;$script:stageEdits=@{b=@('login')};$script:job=$null;$status=[pscustomobject]@{Text=''};$script:ptrJob=$null;function BeginOp($action,$payload){$script:sent=@{action=$action;payload=$payload}};$report=[pscustomobject]@{endpoints=@([pscustomobject]@{record_id='a'},[pscustomobject]@{record_id='b'});event_evidence=[pscustomobject]@{events=@()}};if(!(Finalize-LiveEdits $report)){throw 'not_finalized'};if($script:sent.action -ne 'delete_records' -or $script:sent.payload.record_ids[0] -ne 'a' -or $script:sent.payload.entries.b[0] -ne 'login'){throw 'delta_lost'}")

class RevisionContracts(unittest.TestCase):
 def test_delete_controls_main_live_history_and_separate_rule_actions(self):
  s=(BASE/'app/ui-tools.ps1').read_text();self.assertIn('Delete-MainRecords',s);self.assertIn('Delete-LiveRecords',s);self.assertIn('Delete-SelectedCaptures',s);self.assertIn('deletion_consent=$true',s);self.assertNotIn("BeginOp 'apply'",s);self.assertNotIn('Remove-NetFirewallRule',s)
 def test_ptr_popup_has_names_status_and_independent_explicit_worker(self):
  s=(BASE/'app/ui-live.ps1').read_text();helper=(BASE/'app/ui-tools.ps1').read_text();self.assertIn("Column $g 'hostname'",s);self.assertIn("Column $eg 'ptrstate'",s);self.assertIn('Start-LivePtr $false',s);self.assertIn('$script:ptrJob=@{Process=',helper);self.assertIn('Select-Object -First 100',helper);self.assertNotIn('$script:job=@{',helper)
 def test_canonical_ingestion_precedes_popup_and_popup_exception_isolated(self):
  s=(BASE/'app/ui.ps1').read_text();self.assertLess(s.index('Accept-CaptureReport $r.observation ($j.Action'),s.index('Finish-LiveCapture $r.observation'));self.assertIn("Write-UiDiagnostic 'popup_finalize'",s)
 def test_no_automatic_hosts_change_or_dns_flush(self):
  s=(BASE/'app/hosts_edit.py').read_text();self.assertIn('hosts_edit_consent',s);self.assertIn('hosts_changed_externally_read_again',s);self.assertIn("'hosts-backups'",s)
  for command in ('ipconfig','Clear-DnsClientCache','subprocess.run','Set-DnsClient'):self.assertNotIn(command,s)

if __name__=='__main__':unittest.main()
