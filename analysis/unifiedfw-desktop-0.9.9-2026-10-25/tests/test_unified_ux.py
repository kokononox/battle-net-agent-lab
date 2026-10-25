import copy,json,pathlib,sys,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from policy import new_config,program_id,blacklist_entry,compile_plan
import blacklist_inventory as b
class UnifiedUXTests(unittest.TestCase):
 def setUp(self):
  c=new_config();c['programs']=[dict(id=program_id(p),path=p,sha256='a'*64,enabled=True) for p in (r'C:\Apps\Game.exe',r'C:\Apps\Agent.exe')];c['blacklist']=[blacklist_entry([p['id'] for p in c['programs']],'8.8.8.8','TCP',443)]
  self.s=dict(owner='a'*32,config=c);self.rules=compile_plan(c,self.s['owner'])['rules'];self.snap=dict(available=True,complete=True,checked_utc='2026-10-25T00:00:00Z',rules=[dict(name=r['name']) for r in self.rules])
 def classify(self,**kw):return b.classify(self.s,{**self.snap,**kw})
 def test_saved_does_not_imply_applied(self):self.assertEqual(self.classify(available=False,complete=False,rules=[])['entries'][0]['status'],'unknown')
 def test_full_actual_readback(self):
  r=self.classify();self.assertEqual(r['entries'][0]['status'],'active_verified');self.assertEqual(r['entries'][0]['matched_rules'],2)
 def test_partial_is_not_full_active(self):self.assertEqual(self.classify(rules=self.snap['rules'][:1])['entries'][0]['status'],'partial')
 def test_empty_complete_snapshot_not_matching(self):self.assertEqual(self.classify(rules=[])['entries'][0]['status'],'not_matching_in_snapshot')
 def test_empty_partial_snapshot_is_unknown(self):self.assertEqual(self.classify(complete=False,rules=[])['entries'][0]['status'],'unknown')
 def test_disabled_programs_not_effective_rules(self):
  for p in self.s['config']['programs']:p['enabled']=False
  self.assertEqual(self.classify(rules=[])['entries'][0]['status'],'no_enabled_program')
 def test_stale_rules_remain_visible_after_saved_deletion(self):
  self.s['config']['blacklist']=[];r=self.classify();self.assertEqual(len(r['orphan_rules']),2);self.assertEqual(r['entries'],[])
 def test_changed_target_does_not_adopt_old_rules(self):
  self.s['config']['blacklist']=[blacklist_entry([p['id'] for p in self.s['config']['programs']],'1.1.1.1','TCP',443)];r=self.classify();self.assertEqual(r['entries'][0]['status'],'not_matching_in_snapshot');self.assertEqual(len(r['orphan_rules']),2)
 def test_read_only_source_no_firewall_mutation(self):
  s=(ROOT/'app/blacklist_inventory.py').read_text()
  for t in ('native_result(',"native('apply'",'New-NetFirewallRule','Remove-NetFirewallRule','Set-NetFirewallRule','shell=True'):self.assertNotIn(t,s)
  self.assertIn('inventory-read.ps1',s);self.assertIn('timeout=45',s)
 def test_no_save_tab_and_single_primary_save(self):
  s=(ROOT/'app/ui-workspace.ps1').read_text('utf-8-sig');self.assertNotIn('$savedIPTab',s);self.assertIn("$ipSave=Local-Button 'ذخیرهٔ بلک‌لیست'",s);self.assertIn("@('native','وضعیت قواعد ویندوز')",s)
 def test_confirmation_is_click_only_and_default_cancel(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');body=s[s.index('function ConfirmText('):s.index('$add.Add_Click')]
  self.assertNotIn('$typed',body);self.assertNotIn('Add_TextChanged',body);self.assertIn('$text.ReadOnly=$true',body);self.assertIn('$dialog.AcceptButton=$cancel',body);self.assertIn("$dialog.ShowDialog($form) -eq 'OK'",body)
 def test_audit_and_hosts_keep_preview_and_confirmation_checks(self):
  s=(ROOT/'app/ui-hosts-reset.ps1').read_text('utf-8-sig');self.assertIn('plan_digest',s);self.assertIn('ConfirmText',s)
  self.assertIn("payload.get('confirmation')!=CONSENTS[action]",(ROOT/'app/audit_ops.py').read_text())
 def test_recovery_confirmations_not_typed(self):
  for name in ('recovery.py','audit_ops.py'):
   s=(ROOT/'app'/name).read_text();self.assertNotIn("input('Type",s);self.assertNotIn('Confirm by typing',s);self.assertIn('MessageBoxW',s)
 def test_snapshot_is_invalidated_on_native_error(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertIn("@('native_apply_blacklist','native_restore','workspace_blacklist_inventory')){$script:blacklistInventory=$null",s)
 def test_required_core_unchanged(self):
  base=pathlib.Path('/data/ufw-base')
  if not base.exists():self.skipTest('Comparison source unavailable outside build environment')
  for name in ('lab/session-core.ps1','app/audit-worker.ps1','app/hosts_reset.py','app/hosts_edit.py'):
   self.assertEqual((ROOT/name).read_bytes(),(base/name).read_bytes())

 def test_native_write_functions_unchanged_legacy_detection_extended(self):
  base=pathlib.Path('/data/ufw-base')
  if not base.exists():self.skipTest('Comparison source unavailable outside build environment')
  actual=(ROOT/'lab/native.ps1').read_text('utf-8-sig');previous=(base/'lab/native.ps1').read_text('utf-8-sig')
  self.assertEqual(actual.split('function UReadEnvironment')[0],previous.split('function UReadEnvironment')[0])
  self.assertEqual(actual.split('function UAssertEnvironment')[1],previous.split('function UAssertEnvironment')[1])
  self.assertIn(r'SSTP\s+Kill\s+Switch',actual)

if __name__=='__main__':unittest.main()
