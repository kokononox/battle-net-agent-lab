import copy,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'lab')]
from policy import PolicyError,windows_path,digest
from state import Store,locked,atomic_json
import desktop_ops as ops
import desktop_cli as api

class DesktopTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name);self.sha='a'*64
  self.store=Store(self.base/'store',lambda p:dict(path=windows_path(p),sha256=self.sha))
  s=self.store.register([r'C:\Apps\One.exe',r'C:\Other\One.exe'],0)
  self.ids=[p['id'] for p in s['config']['programs']]
  self.store.add_blacklist(self.ids,'8.8.8.8','TCP',443,1)
 def tearDown(self):self.tmp.cleanup()
 def prepare(self,**kw):return ops.handle(self.store,'native_prepare',dict(generation=2,**kw))['preparation']
 def payload(self,p):return dict(generation=p['generation'],plan_digest=p['plan_digest'],confirmation='I ACCEPT LAB NETWORK CHANGES')
 def test_prepare_no_native_and_exact_rule_snapshot(self):
  with patch.object(ops,'native_result') as call:
   p=self.prepare();call.assert_not_called()
  self.assertEqual(p['rule_count'],2);self.assertEqual(len(p['rules']),2)
  self.assertEqual(len({x['id'] for x in p['programs']}),2)
  self.assertTrue(p['LAB_only']);self.assertEqual(p['mode'],'blacklist_only')
 def test_apply_only_after_confirmation_digest_generation(self):
  p=self.prepare()
  with patch.object(ops,'native_result',return_value={'native_ok':True}) as call:
   self.assertTrue(ops.handle(self.store,'native_apply_blacklist',self.payload(p))['native_ok'])
   call.assert_called_once();self.assertEqual(call.call_args.args[0],'apply')
 def test_missing_confirmation_no_native(self):
  with patch.object(ops,'native_result') as call:
   with self.assertRaisesRegex(PolicyError,'confirmation'):ops.handle(self.store,'native_apply_blacklist',{'generation':2})
   call.assert_not_called()
 def test_digest_mismatch_no_native(self):
  q=self.payload(self.prepare());q['plan_digest']='0'*64
  with patch.object(ops,'native_result') as call:
   with self.assertRaisesRegex(PolicyError,'plan_changed'):ops.handle(self.store,'native_apply_blacklist',q)
   call.assert_not_called()
 def test_stale_generation_no_native(self):
  q=self.payload(self.prepare());self.store.configure('blacklist_only',[],2)
  with patch.object(ops,'native_result') as call:
   with self.assertRaisesRegex(PolicyError,'config_changed'):ops.handle(self.store,'native_apply_blacklist',q)
   call.assert_not_called()
 def test_bool_generation_refused(self):
  with self.assertRaisesRegex(PolicyError,'config_changed'):ops.handle(self.store,'native_prepare',{'generation':True})
 def test_binary_changed_after_prepare(self):
  q=self.payload(self.prepare());self.sha='b'*64
  with patch.object(ops,'native_result') as call:
   with self.assertRaisesRegex(PolicyError,'binary_changed'):ops.handle(self.store,'native_apply_blacklist',q)
   call.assert_not_called()
 def test_apply_holds_config_lock_through_native(self):
  def native(*args):
   with self.assertRaisesRegex(PolicyError,'another_config_operation'):self.store.read()
   return {'native_ok':True}
  with patch.object(ops,'native_result',side_effect=native):ops.handle(self.store,'native_apply_blacklist',self.payload(self.prepare()))
 def test_global_modes_cannot_native_apply(self):
  for mode in ('vpn_allowlist','full_isolation'):
   self.store.configure(mode,['8.8.8.8'],self.store.read()['config']['generation'])
   with patch.object(ops,'native_result') as call:
    with self.assertRaisesRegex(PolicyError,'global_whitelist_not_qualified'):ops.handle(self.store,'native_prepare',{'generation':self.store.read()['config']['generation']})
    call.assert_not_called()
   self.assertEqual(self.store.read()['config']['mode'],mode)
 def test_legacy_ack_not_silently_granted(self):
  # request_for enforces the actual legacy gate; no fake legacy schema is persisted.
  state=self.store.read();state['config']['legacy_imports']=[{'kind':'blacklist','rules_may_still_be_active':True}]
  with patch.object(self.store,'_read',return_value=state):
   with self.assertRaisesRegex(PolicyError,'legacy_imports_unresolved'):self.prepare()
   self.assertTrue(self.prepare(legacy_ack='OLD TOOLS RESTORED')['LAB_only'])
 def test_restore_exact_confirmation_and_status_without_config(self):
  with patch.object(ops,'native_result',return_value={'native_ok':True}) as call:
   with self.assertRaisesRegex(PolicyError,'restore_confirmation'):ops.handle(None,'native_restore',{})
   ops.handle(None,'native_restore',{'confirmation':'RESTORE'});self.assertEqual(call.call_args.args,('restore',))
   ops.handle(None,'native_status',{});self.assertEqual(call.call_args.args,('status',))
 def test_unrecognized_native_action_rejected(self):
  with self.assertRaisesRegex(PolicyError,'unknown'):ops.handle(None,'native_force_restore',{})
 def test_native_result_keeps_failure_and_private_local_receipt(self):
  folder=self.base/'private-state/lab-jobs/test';folder.mkdir(parents=True);p=folder/'result.json'
  p.write_text(json.dumps(dict(ok=False,error='fixture',session={'id':'fixture','entries':[{}]})))
  def native(*a):print('Result file:',p);return 1
  with patch.object(ops,'BASE',self.base),patch.object(ops,'verify_package'),patch.object(ops,'native',side_effect=native):r=ops.native_result('restore')
  self.assertFalse(r['native_ok']);self.assertFalse(r['protection_verified']);self.assertEqual(r['native']['session_summary']['entry_count'],1)
 def test_native_result_cannot_escape_local_job_folder(self):
  p=self.base/'result.json';p.write_text('{"ok":true}')
  def native(*a):print('Result file:',p);return 0
  with patch.object(ops,'BASE',self.base),patch.object(ops,'verify_package'),patch.object(ops,'native',side_effect=native):
   with self.assertRaisesRegex(PolicyError,'scope'):ops.native_result('status')
 def test_api_native_exception_never_claims_no_changes(self):
  job=self.base/'private-state/jobs/fixture';job.mkdir(parents=True);req=job/'request.json';out=job/'response.json'
  req.write_text(json.dumps(dict(action='native_apply_blacklist',payload={})))
  with patch.object(api,'BASE',self.base),patch.object(ops,'handle',side_effect=RuntimeError('native_result_missing')):
   self.assertEqual(api.execute(req,out),1)
  r=json.loads(out.read_text());self.assertFalse(r['ok']);self.assertNotIn('firewall_changed',r);self.assertIn('unknown_if_native_started',r['firewall_change_status'])
 def test_api_original_apply_still_disabled(self):
  job=self.base/'private-state/jobs/fixture';job.mkdir(parents=True);req=job/'request.json';out=job/'response.json'
  req.write_text(json.dumps(dict(action='apply',payload={})))
  with patch.object(api,'BASE',self.base):self.assertEqual(api.execute(req,out),1)
  self.assertIn('disabled',json.loads(out.read_text())['error'])
 def test_ui_stable_ids_async_and_no_forced_kill(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig')
  for token in ('CurrentCellDirtyStateChanged','CommitEdit','Rows[$i].Tag=$item.id','script:checks','plan_digest','native_restore','HasExited','RightToLeft','AutoScaleMode','ConfirmText'):
   self.assertIn(token,s)
  for token in ('DoEvents','Stop-Process','RedirectStandardError=$true','ExecutionPolicy Bypass','.Kill('):self.assertNotIn(token,s)
  self.assertTrue((ROOT/'app/ui.ps1').read_bytes().startswith(b'\xef\xbb\xbf'))
if __name__=='__main__':unittest.main()
