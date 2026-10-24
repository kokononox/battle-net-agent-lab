import copy,json,pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tests')]
import audit_ops as ao,baseline_ops as bo,monitor_evidence as me
from policy import PolicyError
from test_baseline import capture

class DenialTests(unittest.TestCase):
 def setUp(self):
  self.c=capture();p=self.c['processes'][0]
  self.e=dict(record_id='e'*32,program_id=p['program_id'],program_path=p['program_path'],pid=p['pid'],process_start_ticks=p['process_start_ticks'],event_record_id=12,observed_utc=p['last_seen_utc'],kind='wfp_connection_block',direction='outbound',protocol='TCP',ip='8.8.8.8',port=443,filter_id='42')
 def events(self):
  self.c['event_evidence']=dict(events=[self.e]);return bo.validate(self.c)['event_evidence']
 def test_new_process_denial_without_TCP(self):
  self.c['endpoints']=[];v=self.events();self.assertEqual(len(v['events']),1);self.assertFalse(v['events'][0]['rule_owner_verified'])
 def test_birth_preserved_after_double_normalize(self):self.assertEqual(self.events()['events'][0]['process_start_ticks'],self.e['process_start_ticks'])
 def test_old_PID_denial_without_birth_discarded(self):self.e.pop('process_start_ticks');self.assertFalse(self.events()['events'])
 def test_different_birth_not_same_PID(self):self.e['process_start_ticks']=str(int(self.e['process_start_ticks'])+1);self.assertFalse(self.events()['events'])
 def test_before_baseline_denial_discarded(self):self.e['process_start_ticks']=str(int(self.c['baseline_cutoff_ticks'])-1);self.assertFalse(self.events()['events'])
 def test_future_event_discarded(self):self.e['observed_utc']='2026-10-24T12:00:01Z';self.assertFalse(self.events()['events'])
 def test_before_capture_event_discarded(self):self.e['observed_utc']='2026-10-24T11:59:59Z';self.assertFalse(self.events()['events'])
 def test_birth_after_event_discarded(self):self.e['process_start_ticks']=str(me.utc_ticks(me.instant(self.e['observed_utc']))+1);self.assertFalse(self.events()['events'])
 def test_inbound_not_claimed_as_outbound(self):self.e['direction']='inbound';self.assertFalse(self.events()['events'])
 def test_invalid_protocol_not_claimed(self):self.e['protocol']='ICMP';self.assertFalse(self.events()['events'])
 def test_zero_port_not_claimed(self):self.e['port']=0;self.assertFalse(self.events()['events'])
 def test_other_path_not_same_exename(self):self.e['program_path']=r'C:\Other\Game.exe';self.assertFalse(self.events()['events'])
 def test_normal_selected_mode_still_accepts_logged_path_without_birth(self):
  self.e.pop('process_start_ticks');v=me.normalize(dict(events=[self.e]),self.c['programs']);self.assertEqual(len(v['events']),1);self.assertNotIn('process_start_ticks',v['events'][0])
 def test_no_packet_or_own_rule_claim(self):
  row=self.events()['events'][0];self.assertTrue(row['connection_denial_event']);self.assertFalse(row['packet_drop_verified']);self.assertFalse(row['HTTP_request_verified']);self.assertEqual(row['source'],'Security_5157')
 def test_cap_and_coverage_still_honest(self):v=self.events();self.assertEqual(v['cap'],1000);self.assertFalse(v['streams']['wfp']['coverage_verified'])
 def test_audit_consent_before_OS_or_launch(self):
  for action in ao.CONSENTS:
   with self.subTest(action=action),patch.object(ao.subprocess,'run') as run:
    with self.assertRaisesRegex(PolicyError,'explicit_audit_confirmation'):ao.handle(None,action,{},pathlib.Path('/unused'))
    run.assert_not_called()
 def test_audit_other_category_not_accepted(self):
  with self.assertRaisesRegex(PolicyError,'audit_action'):ao.handle(None,'audit_disable_everything',{},pathlib.Path('/unused'))
 def test_audit_nonWindows_does_not_spawn(self):
  with patch.object(ao,'os',types.SimpleNamespace(name='posix')),patch.object(ao.subprocess,'run') as run:
   with self.assertRaisesRegex(PolicyError,'requires_Windows'):ao.handle(None,'audit_status',{},pathlib.Path('/unused'))
   run.assert_not_called()
 def invoke(self,action,answer=None,code=0):
  with tempfile.TemporaryDirectory() as tmp:
   job=pathlib.Path(tmp);calls=[];verified=[]
   def run(cmd,**kw):
    calls.append((cmd,kw))
    if answer is not None:(job/'audit-result.json').write_text(json.dumps(answer))
    return types.SimpleNamespace(returncode=code)
   console=types.SimpleNamespace(verify_package=lambda:verified.append(True))
   with patch.object(ao,'os',types.SimpleNamespace(name='nt',environ={'SystemRoot':r'C:\Windows'})),patch.dict(sys.modules,{'console':console}),patch.object(ao.subprocess,'run',side_effect=run):
    result=ao.handle(None,action,{'confirmation':ao.CONSENTS.get(action,''),'subcategory':'evil','path':'untrusted'},job)
   return result,calls,json.loads((job/'audit-request.json').read_text()),verified
 def test_only_fixed_worker_and_confirmation_no_payload_GUID(self):
  value,calls,request,verified=self.invoke('audit_enable',dict(ok=True,audit=dict(failure_enabled=True)))
  cmd,kw=calls[0];self.assertEqual(request,dict(action='enable',confirmation=ao.CONSENTS['audit_enable']));self.assertIn(str(ROOT/'app/audit-worker.ps1'),cmd);self.assertTrue(verified);self.assertFalse(value['firewall_changed']);self.assertNotIn('shell',kw)
 def test_mutation_no_timeout_no_forced_kill(self):
  _,calls,_,_=self.invoke('audit_restore',dict(ok=True,audit={}))
  self.assertNotIn('timeout',calls[0][1]);s=(ROOT/'app/audit_ops.py').read_text();self.assertNotIn('.kill(',s);self.assertNotIn('.terminate(',s)
 def test_missing_response_unknown_no_retry(self):
  with self.assertRaisesRegex(PolicyError,'change_unknown'):self.invoke('audit_enable')
 def test_worker_failure_uncertainty(self):
  with self.assertRaisesRegex(PolicyError,'use_status_not_retry'):self.invoke('audit_restore',dict(ok=False,error='readback_conflict'),1)
 def test_no_policy_mutation_in_collectors(self):
  for name in ('live-events.ps1','baseline.ps1','baseline-wfp.ps1'):
   s=(ROOT/'app'/name).read_text(encoding='utf-8-sig');self.assertNotIn('::Write(',s);self.assertNotIn('EnableSecurityPrivilege()',s);self.assertNotIn('auditpol ',s)
 def test_audit_recovery_is_distinct(self):
  s=(ROOT/'Audit-Recovery.cmd').read_text();self.assertIn('audit_ops.py',s);self.assertNotIn('native_restore',s)
 def test_GUI_explicit_confirmation_no_automatic_enable(self):
  s=(ROOT/'app/ui-denials.ps1').read_text(encoding='utf-8-sig');self.assertIn("if(ConfirmText",s);self.assertIn("BeginOp 'audit_status'",s);self.assertIn('Set-DenialControls',s)
 def test_actual_WFP_not_filtered_by_presence(self):
  s=(ROOT/'app/ui-evidence.ps1').read_text(encoding='utf-8-sig');self.assertIn('Test-MonitorRowVisible $r $onlyPresent.Checked',s);self.assertIn('Get-DenialPulse $Seen',s);self.assertIn('Get-DenialGroups $Frame.event_evidence.events',s)

 def test_mutation_action_not_read_from_editable_job_JSON(self):
  _,calls,_,_=self.invoke('audit_enable',dict(ok=True,audit={}))
  cmd=calls[0][0];self.assertNotIn('-Request',cmd);self.assertEqual(cmd[cmd.index('-Action')+1],'enable');self.assertEqual(cmd[cmd.index('-Confirmation')+1],ao.CONSENTS['audit_enable'])
  worker=(ROOT/'app/audit-worker.ps1').read_text(encoding='utf-8-sig');self.assertNotIn('ReadAllText($Request)',worker)
