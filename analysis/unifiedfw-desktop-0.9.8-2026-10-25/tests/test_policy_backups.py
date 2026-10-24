import copy,json,pathlib,sys,tempfile,unittest,os
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
import policy_backups as b
from policy import PolicyError
from state import Store
from workspace_ops import handle as workspace
class PolicyBackupTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.t.name);self.store=Store(self.root/'state',lambda p:dict(path=p,sha256='a'*64));self.first=self.store.read();self.store.register([r'C:\Apps\Game.exe'],0);self.pid=self.store.read()['config']['programs'][0]['id'];self.store.add_blacklist([self.pid],'8.8.8.8','TCP',443,1);self.store.configure('vpn_allowlist',['1.1.1.1'],2)
 def tearDown(self):self.t.cleanup()
 def call(self,action,scope='blacklist',**kw):
  p=dict(scope=scope,generation=self.store.read()['config']['generation'],confirmation='RESTORE POLICY SETTINGS' if action=='backup_restore' else 'RESET POLICY SETTINGS');p.update(kw);return workspace(self.store,'workspace_policy_'+action,p,self.root)
 def ui(self):return dict(ip_rows=[dict(program_ids=[],target='::ffff:8.8.8.8',protocol='',port=0,source_path=r'C:\Apps\Unregistered.exe')],whitelist_text='unsaved.example',mode='full_isolation')
 def test_auto_backup_precedes_every_valid_update(self):
  items=b.list_backups(self.store)['items'];self.assertEqual(len(items),3);self.assertEqual(sorted(x['generation'] for x in items),[0,1,2]);saved=b.read_backup(self.store,self.store.last_backup_id,self.first['owner']);self.assertEqual(saved['state']['config']['generation'],2)
 def test_initial_empty_state_preserves_owner(self):
  items=b.list_backups(self.store)['items'];v=b.read_backup(self.store,items[-1]['id'],self.first['owner']);self.assertEqual(v['state'],self.first)
 def test_backup_failure_prevents_settings_write(self):
  before=self.store.file.read_bytes()
  with patch.object(b,'atomic_json',side_effect=OSError('disk_full')),self.assertRaises(OSError):self.store.configure('blacklist_only',[],3)
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_readback_failure_prevents_settings_write(self):
  before=self.store.file.read_bytes()
  with patch.object(b,'read_backup',side_effect=PolicyError('readback')),self.assertRaises(PolicyError):self.store.configure('blacklist_only',[],3)
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_stale_generation_no_change_no_extra_backup(self):
  n=len(b.list_backups(self.store)['items']);before=self.store.file.read_bytes()
  with self.assertRaises(PolicyError):self.store.configure('blacklist_only',[],0)
  self.assertEqual(self.store.file.read_bytes(),before);self.assertEqual(len(b.list_backups(self.store)['items']),n)
 def test_invalid_update_no_backup(self):
  n=len(b.list_backups(self.store)['items'])
  with self.assertRaises(PolicyError):self.store.configure('bad',[],3)
  self.assertEqual(len(b.list_backups(self.store)['items']),n)
 def test_blacklist_defaults_only_blacklist(self):
  before=self.store.read();r=self.call('defaults',ui_snapshot=self.ui());c=r['state']['config'];self.assertEqual(c['blacklist'],[])
  for key in ('whitelist','mode','programs','legacy_imports'):self.assertEqual(c[key],before['config'][key])
  self.assertEqual(r['state']['owner'],before['owner']);self.assertFalse(r['active_rules_restored']);self.assertFalse(r['firewall_changed'])
 def test_whitelist_defaults_sets_safe_saved_mode_preserves_blacklist(self):
  before=self.store.read();c=self.call('defaults','whitelist')['state']['config'];self.assertEqual(c['whitelist'],[]);self.assertEqual(c['mode'],'blacklist_only');self.assertEqual(c['blacklist'],before['config']['blacklist']);self.assertEqual(c['programs'],before['config']['programs'])
 def test_defaults_backup_contains_unsaved_incomplete_drafts(self):
  ui=self.ui();r=self.call('defaults',ui_snapshot=ui);v=b.read_backup(self.store,r['policy_settings_result']['prechange_backup_id'],self.first['owner']);self.assertEqual(v['ui_snapshot'],ui);self.assertEqual(v['state']['config']['generation'],3)
 def test_restore_only_selected_scope_and_new_generation(self):
  old=self.store.read();r=self.call('defaults',ui_snapshot=self.ui());ident=r['policy_settings_result']['prechange_backup_id'];self.store.configure('blacklist_only',['9.9.9.9'],4)
  r=self.call('backup_restore',backup_id=ident);c=r['state']['config'];self.assertEqual(c['blacklist'],old['config']['blacklist']);self.assertEqual(c['whitelist'],['9.9.9.9']);self.assertEqual(c['mode'],'blacklist_only');self.assertEqual(c['generation'],6);self.assertEqual(r['policy_settings_result']['restored_UI'],self.ui());self.assertNotEqual(r['policy_settings_result']['prechange_backup_id'],ident)
 def test_restore_whitelist_mode_without_replacing_blacklist(self):
  r=self.call('defaults','whitelist');ident=r['policy_settings_result']['prechange_backup_id'];self.store.delete_blacklist([self.store.read()['config']['blacklist'][0]['id']],4);r=self.call('backup_restore','whitelist',backup_id=ident);c=r['state']['config'];self.assertEqual(c['whitelist'],['1.1.1.1']);self.assertEqual(c['mode'],'vpn_allowlist');self.assertEqual(c['blacklist'],[])
 def test_restore_missing_registered_program_rejects_atomically(self):
  r=self.call('defaults');ident=r['policy_settings_result']['prechange_backup_id'];self.store.remove([self.pid],4);before=self.store.file.read_bytes()
  with self.assertRaises(PolicyError):self.call('backup_restore',backup_id=ident)
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_wrong_consent_no_change(self):
  before=self.store.file.read_bytes()
  with self.assertRaises(PolicyError):self.call('defaults',confirmation='')
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_bad_scope_no_change(self):
  before=self.store.file.read_bytes()
  with self.assertRaises(PolicyError):self.call('defaults','all_windows_firewall')
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_corrupt_backup_rejected_not_deleted(self):
  ident=self.store.last_backup_id;p=b.directory(self.store)/(ident+'.json');v=json.loads(p.read_text());v['state']['config']['whitelist']=['8.8.4.4'];p.write_text(json.dumps(v));before=self.store.file.read_bytes()
  with self.assertRaisesRegex(PolicyError,'hash'):self.call('backup_restore',backup_id=ident)
  self.assertEqual(self.store.file.read_bytes(),before);self.assertTrue(p.exists());self.assertEqual(b.list_backups(self.store)['invalid_or_other_owner'],1)
 def test_wrong_owner_rejected_even_with_recomputed_hash(self):
  ident=self.store.last_backup_id;p=b.directory(self.store)/(ident+'.json');v=json.loads(p.read_text());v['state']['owner']='f'*32;v['sha256']=b.fingerprint({k:x for k,x in v.items() if k!='sha256'});p.write_text(json.dumps(v))
  with self.assertRaisesRegex(PolicyError,'other_owner'):self.call('backup_restore',backup_id=ident)
 def test_path_traversal_rejected(self):
  for ident in ('../settings','C:\\settings','A'*32,None):
   with self.assertRaises(PolicyError):b.read_backup(self.store,ident,self.first['owner'])
 def test_symlink_backup_rejected(self):
  ident=self.store.last_backup_id;p=b.directory(self.store)/(ident+'.json');real=self.root/'outside.json';p.rename(real);p.symlink_to(real)
  with self.assertRaisesRegex(PolicyError,'reparse'):b.read_backup(self.store,ident,self.first['owner'])
 def test_hardlink_backup_rejected(self):
  ident=self.store.last_backup_id;p=b.directory(self.store)/(ident+'.json');os.link(p,self.root/'copy-link')
  with self.assertRaisesRegex(PolicyError,'link'):b.read_backup(self.store,ident,self.first['owner'])
 def test_ui_snapshot_limits_reject_before_change(self):
  for ui in ({},dict(self.ui(),mode='bad'),dict(self.ui(),ip_rows=[dict(self.ui()['ip_rows'][0],port=-1)]),dict(self.ui(),whitelist_text='x'*262145)):
   before=self.store.file.read_bytes()
   with self.assertRaises(PolicyError):self.call('defaults',ui_snapshot=ui)
   self.assertEqual(self.store.file.read_bytes(),before)
 def test_list_is_readonly(self):
  before={str(p):p.read_bytes() for p in b.directory(self.store).glob('*.json')};r=self.call('backup_list');self.assertIn('policy_backups',r);self.assertEqual(before,{str(p):p.read_bytes() for p in b.directory(self.store).glob('*.json')})
 def test_no_firewall_or_hosts_mutation_in_adapter(self):
  s=(ROOT/'app/policy_backups.py').read_text()
  for t in ('subprocess','native_result','New-NetFirewallRule','Remove-NetFirewallRule','netsh','hosts_edit','Set-NetFirewallProfile'):self.assertNotIn(t,s)
 def test_UI_backup_selection_is_after_job_cleanup(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertLess(s.index('try{$j.process.Dispose()}finally{'),s.index('Show-PolicyBackupList $policyBackupsPrepared'))
