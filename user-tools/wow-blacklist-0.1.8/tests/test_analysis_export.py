import hashlib,json,os,subprocess,sys,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,BlacklistError,atomic,parse_list,spec
from capture_store import STAGES
import test_manager as tm

class AnalysisTests(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def capture(self,ident='a'*32,rows=None):
  self.m.collector=lambda p,j:dict(seconds=60,query_errors=0,capture_started_utc='2026-01-01T00:00:00Z',capture_ended_utc='2026-01-01T00:01:00Z',endpoints=rows or [dict(ip='2.19.198.11',port=80,pid=12,process_started_utc='2026-01-01T00:00:01Z',fresh_process_seen=True,samples=2,state_samples={'SynSent':1,'Established':1},first_seen_utc='2026-01-01T00:00:02Z',last_seen_utc='2026-01-01T00:00:03Z')])
  return self.m.run('observe',dict(program=str(self.exe),seconds=60),ident)['observation']
 def export(self,ids=None,**kw):
  result=self.m.run('export_analysis',dict(capture_ids=ids or ['a'*32],program=str(self.exe),**kw),'e'*32)['export'];path=self.m.output/result['filename']
  with zipfile.ZipFile(path) as z:
   self.assertIsNone(z.testzip());files={n:z.read(n) for n in z.namelist()}
  self.assertEqual(result['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
  return result,json.loads(files['analysis.json']),files
 def inventory(self,text):
  entries=parse_list(text)
  def fw(p,j):
   self.calls.append(p);return dict(inventory_verified=True,entries=[spec(self.m.owner(),str(self.exe),e) for e in entries],checked_utc='2026-01-01T00:00:00Z')
  self.m.fw=fw
 def test_default_unknown_and_stable_id(self):
  c=self.capture();r=c['endpoints'][0];self.assertEqual(r['context']['stage'],'unknown');self.assertEqual(r['context']['source'],'not_set');self.assertEqual(r['record_id'],self.m.captures.read(c['capture_id'])['endpoints'][0]['record_id'])
 def test_annotation_persists_without_changing_raw_firewall_or_blacklist(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];path=self.m.captures.capture_path(c['capture_id']);raw=path.read_bytes();config=self.m.config_path.read_bytes();txt=self.m.text_path.read_bytes();self.calls.clear()
  self.m.run('annotate_observation',dict(capture_id=c['capture_id'],entries={key:'launch'}));r=self.m.run('load_observation',dict(capture_id=c['capture_id']))['observation']['endpoints'][0]
  self.assertEqual(r['context']['stage'],'launch');self.assertFalse(r['context']['event_time_verified']);self.assertEqual(path.read_bytes(),raw);self.assertEqual(self.m.config_path.read_bytes(),config);self.assertEqual(self.m.text_path.read_bytes(),txt);self.assertEqual(self.calls,[])
 def test_same_endpoint_different_captures_independent(self):
  a=self.capture();b=self.capture('b'*32);key=a['endpoints'][0]['record_id'];self.m.captures.save_annotations(a['capture_id'],{key:'login'});self.assertNotEqual(key,b['endpoints'][0]['record_id']);self.assertEqual(self.m.captures.read(b['capture_id'])['endpoints'][0]['context']['stage'],'unknown')
 def test_clear_and_unchanged_annotation_timestamp(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];self.m.captures.save_annotations(c['capture_id'],{key:'in_game'});before=self.m.captures.annotations(c['capture_id']);self.assertEqual(self.m.captures.save_annotations(c['capture_id'],{key:'in_game'})['changed'],0);self.assertEqual(before,self.m.captures.annotations(c['capture_id']));self.m.captures.save_annotations(c['capture_id'],{key:'unknown'});self.assertEqual(self.m.captures.read(c['capture_id'])['endpoints'][0]['context']['stage'],'unknown')
 def test_invalid_stage_and_record_rejected(self):
  c=self.capture();key=c['endpoints'][0]['record_id']
  for edits in ({key:'automatic_guess'},{'0'*32:'launch'},[],{key:['not_a_stage']}):
   with self.assertRaises(BlacklistError):self.m.run('annotate_observation',dict(capture_id=c['capture_id'],entries=edits))
 def test_history_load_and_annotations_without_owner_or_program(self):
  c=self.capture();self.calls.clear()
  for p in self.m.private.glob('owner-id*'):p.unlink()
  self.exe.unlink();self.assertEqual(len(self.m.run('history')['history']['entries']),1);self.m.run('load_observation',dict(capture_id=c['capture_id']));self.m.run('annotate_observation',dict(capture_id=c['capture_id'],entries={}));self.assertEqual(self.calls,[])
 def test_history_excludes_classification_and_marks_invalid(self):
  c=self.capture();atomic(self.m.output/('destinations-classification-'+'b'*32+'.json'),{});self.m.captures.capture_path('c'*32).write_text('bad');r=self.m.captures.history();self.assertEqual(r['total_files'],2);self.assertEqual(r['invalid_files'],1);self.assertEqual(len(r['entries']),1)
 def test_history_limit_explicit(self):
  self.capture();self.capture('b'*32)
  with patch('capture_store.MAX_HISTORY',1):r=self.m.captures.history()
  self.assertTrue(r['truncated']);self.assertEqual(r['limit'],1);self.assertEqual(len(r['entries']),1)
 def test_legacy_capture_missing_start_snapshot_is_unavailable(self):
  c=self.capture();p=self.m.captures.capture_path(c['capture_id']);raw=json.loads(p.read_text());raw.pop('block_snapshot_start');raw['version']='0.1.4';atomic(p,raw);r=self.m.captures.read(c['capture_id']);self.assertFalse(r['block_snapshot_start']['available']);self.export()
 def test_corrupt_sidecar_reported_and_not_overwritten(self):
  c=self.capture();p=self.m.captures.annotation_path(c['capture_id']);p.parent.mkdir(exist_ok=True);p.write_text('corrupt');self.assertEqual(self.m.captures.read(c['capture_id'])['annotation_state'],'unavailable_or_invalid')
  with self.assertRaises(BlacklistError):self.m.run('annotate_observation',dict(capture_id=c['capture_id'],entries={}))
  self.assertEqual(p.read_text(),'corrupt')
 def test_ids_cannot_escape_output(self):
  for ident in ('../settings','A'*32,None,[], 'a'*33):
   with self.assertRaises(BlacklistError):self.m.run('load_observation',dict(capture_id=ident))
 def test_oversized_capture_rejected(self):
  self.capture()
  with patch('capture_store.MAX_CAPTURE_BYTES',4):
   with self.assertRaises(BlacklistError):self.m.run('load_observation',dict(capture_id='a'*32))
 def test_export_has_json_readable_and_separate_active_saved_draft(self):
  self.inventory('2.0.0.0/8:80 TCP');self.capture();self.m.run('save',{**self.payload,'text':'8.8.8.8:53 UDP'});self.inventory('1.1.1.1:443 TCP');self.calls.clear();result,r,f=self.export(draft_text='9.9.9.9:443 TCP',draft_dirty=True)
  self.assertEqual(r['active_blacklist_at_export']['entries'][0]['ip'],'1.1.1.1');self.assertEqual(r['saved_desired_blacklist']['entries'][0]['ip'],'8.8.8.8');self.assertEqual(r['editor_draft']['entries'][0]['ip'],'9.9.9.9');self.assertTrue(r['editor_draft']['dirty']);self.assertEqual(r['captures'][0]['block_snapshot']['entries'][0]['ip'],'2.0.0.0/8');self.assertEqual(set(f),{'analysis.json','report.fa.txt','active-blacklist-at-export.txt','saved-blacklist.txt','editor-draft.txt','README.fa.txt'});self.assertEqual([p['action'] for p in self.calls],['inventory']);self.assertFalse(result['automatic_upload'])
 def test_export_start_and_end_snapshots_distinct(self):
  count=[0]
  def fw(p,j):
   count[0]+=1;e=parse_list('1.1.1.1:80 TCP' if count[0]==1 else '8.8.8.8:443 TCP')[0];return dict(inventory_verified=True,entries=[spec(self.m.owner(),str(self.exe),e)])
  self.m.fw=fw;c=self.capture();self.assertEqual(c['block_snapshot_start']['entries'][0]['ip'],'1.1.1.1');self.assertEqual(c['block_snapshot']['entries'][0]['ip'],'8.8.8.8')
 def test_failed_active_snapshot_not_known_empty(self):
  self.capture();self.m.fw=lambda p,j:(_ for _ in ()).throw(OSError('no'));result,r,f=self.export();self.assertFalse(result['active_blacklist_available']);self.assertFalse(r['active_blacklist_at_export']['available']);self.assertIn(b'UNAVAILABLE',f['active-blacklist-at-export.txt'])
 def test_export_all_rows_including_old_and_block_matches(self):
  c=self.capture();row=c['endpoints'][0];self.inventory('2.0.0.0/8:80 TCP');self.capture(rows=[row,{**row,'pid':13,'fresh_process_seen':False}]);result,r,f=self.export();rows=r['captures'][0]['endpoints'];self.assertEqual(result['record_count'],2);self.assertTrue(all(x['covered_by_verified_block'] for x in rows));self.assertFalse(rows[1]['fresh_process_seen'])
 def test_pending_manual_labels_in_export_and_saved(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];result,r,f=self.export(annotations=dict(capture_id=c['capture_id'],entries={key:'dashboard'}));self.assertEqual(r['captures'][0]['endpoints'][0]['context']['stage'],'dashboard');self.assertEqual(result['saved_annotation_capture_id'],c['capture_id']);self.assertEqual(self.m.captures.read(c['capture_id'])['endpoints'][0]['context']['stage'],'dashboard')
 def test_pending_capture_must_be_selected(self):
  self.capture();b=self.capture('b'*32)
  with self.assertRaises(BlacklistError):self.export(annotations=dict(capture_id=b['capture_id'],entries={}))
 def test_export_no_network_and_no_private_identifiers(self):
  self.capture();owner=self.m.owner();self.m.resolver.lookup=lambda *a,**k:(_ for _ in ()).throw(AssertionError('network lookup forbidden'));self.m.hosts_reader=lambda:(_ for _ in ()).throw(AssertionError('hosts forbidden'));result,r,f=self.export();text=''.join(v.decode('utf8') for v in f.values());self.assertNotIn(owner,text);self.assertNotIn(str(self.exe),text);self.assertNotIn(str(self.root),text);self.assertEqual(r['captures'][0]['endpoints'][0]['ptr']['status'],'not_looked_up')
 def test_cached_ptr_only_not_claimed_actual_domain(self):
  self.capture();self.m.resolver.rows=lambda:[dict(ip='2.19.198.11',status='ok',names=['cached.example'],checked_utc=123,stale=True)];_,r,_=self.export();ptr=r['captures'][0]['endpoints'][0]['ptr'];self.assertEqual(ptr['names'],['cached.example']);self.assertTrue(ptr['stale']);self.assertFalse(ptr['actual_domain_verified'])
 def test_export_caps_duplicate_and_record_limits(self):
  self.capture()
  for ids in ([],['a'*32]*2,['a'*32]*51):
   with self.assertRaises(BlacklistError):self.m.run('export_analysis',dict(capture_ids=ids))
  with patch('analysis_export.MAX_RECORDS',0):
   with self.assertRaises(BlacklistError):self.export()
 def test_failed_export_leaves_raw_and_annotations_unchanged(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];raw=self.m.captures.capture_path(c['capture_id']).read_bytes()
  with patch('analysis_export.os.replace',side_effect=OSError('disk')):
   with self.assertRaises(BlacklistError):self.export(annotations=dict(capture_id=c['capture_id'],entries={key:'login'}))
  self.assertEqual(raw,self.m.captures.capture_path(c['capture_id']).read_bytes());self.assertFalse(self.m.captures.annotation_path(c['capture_id']).exists());self.assertFalse(list(self.m.output.glob('*.tmp')))
 def test_reclassification_keeps_record_ids_and_original_snapshot(self):
  c=self.capture();key=c['endpoints'][0]['record_id'];raw=self.m.captures.capture_path(c['capture_id']).read_bytes();r=self.m.run('classify_observation',dict(program=str(self.exe),endpoints=c['endpoints']))['observation'];self.assertEqual(r['endpoints'][0]['record_id'],key);self.assertEqual(raw,self.m.captures.capture_path(c['capture_id']).read_bytes())

class AnalysisUiContracts(unittest.TestCase):
 def test_stage_choices_default_and_editable_cells(self):
  s=(BASE/'app/ui.ps1').read_text();helper=(BASE/'app/ui-analysis.ps1').read_text()
  for label in STAGES.values():self.assertIn(label,s);self.assertIn(label,helper)
  self.assertIn('$stageColumn.ReadOnly=$false',s);self.assertIn('Edit-MainStages @($sender.Rows[$e.RowIndex])',s);self.assertIn('Can-SwitchCapture',s);self.assertIn('$script:annotationsDirty',s)
 def test_separate_export_and_history_all_rows(self):
  s=(BASE/'app/ui-analysis.ps1').read_text();self.assertIn("BeginOp 'export_analysis'",s);self.assertIn("BeginOp 'load_observation'",s);self.assertIn("BeginOp 'annotate_observation'",s);self.assertIn('Get-FileHash -LiteralPath',s);self.assertIn('Utc-Text $_.process_started_utc',s)
 def test_isolated_python_imports_export_modules(self):
  code="import sys;sys.path.insert(0,sys.argv[1]);import backend,capture_store,analysis_export;assert backend.VERSION=='0.1.8'"
  r=subprocess.run([sys.executable,'-I','-c',code,str(BASE/'app')],capture_output=True);self.assertEqual(r.returncode,0,r.stderr.decode())

if __name__=='__main__':unittest.main()

@unittest.skipUnless(os.environ.get('WOW_QA_PWSH'),'Official QA PowerShell runtime required')
class AnalysisPowerShell(unittest.TestCase):
 def test_context_stage_mapping_and_timestamp_roundtrip(self):
  ps=os.environ['WOW_QA_PWSH'];path=str(BASE/'app/ui-analysis.ps1').replace("'","''")
  code=r'''
$ErrorActionPreference='Stop'
function Observation-Key($r){return [string]$r.record_id}
$saveAnnotations=[pscustomobject]@{Text=''}
. ([scriptblock]::Create([IO.File]::ReadAllText('__PATH__')))
$row=[pscustomobject]@{record_id=('a'*32);ip='2.19.198.11';port=80;pid=12;process_started_utc=[datetime]::Parse('2026-01-01T00:00:01Z').ToUniversalTime();fresh_process_seen=$true;samples=1;state_samples=@{SynSent=1};first_seen_utc='2026-01-01T00:00:02Z';last_seen_utc='2026-01-01T00:00:03Z';context=[pscustomobject]@{stage='login'}}
$report=[pscustomobject]@{capture_id=('b'*32);endpoints=@($row)}
Set-CaptureContext $report $true
if((Stage-For $row) -ne 'این ضبط: ورود' -or !$script:observationHistorical -or $script:annotationsDirty){throw 'context_failed'}
if((Stage-Code 'محیط بازی') -ne 'in_game'){throw 'stage_failed'}
$script:observed=@($row);$output=@(Observation-PayloadRows)
if($output.Count -ne 1 -or $output[0].record_id -ne ('a'*32) -or $output[0].process_started_utc -notmatch '^2026-01-01T00:00:01.*Z$'){throw 'timestamp_or_id_failed'}
$output|ConvertTo-Json -Depth 10 -Compress
'''.replace('__PATH__',path)
  r=subprocess.run([ps,'-NoProfile','-NonInteractive','-Command',code],env={**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1'},capture_output=True,timeout=25);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
  row=json.loads(r.stdout);self.assertEqual(row['record_id'],'a'*32);self.assertEqual(row['state_samples'],{'SynSent':1})
