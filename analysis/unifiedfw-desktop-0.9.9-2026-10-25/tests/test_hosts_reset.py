import pathlib,sys,tempfile,unittest,json,types,contextlib,os
from unittest.mock import patch,Mock
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
import hosts_reset as h,hosts_edit as he,hosts_view as hv,desktop_cli as api
from state import Store,atomic_json

class HostsResetTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.t.name);self.store=Store(self.root/'private');self.store.read();self.job=self.root/'job';self.job.mkdir();self.path=self.root/'hosts';self.before=b'# local\r\n0.0.0.0 blocked.example alias.example\r\n:: blocked.example\r\n10.0.0.3 dev.example\r\n';self.path.write_bytes(self.before)
  self.real_flush_dns=h.flush_dns
  self.patches=[patch.object(h,'fixed_hosts',return_value=self.path),patch.object(h,'machine_id',return_value='fixture-machine'),patch.object(h,'require_admin'),patch.object(h,'flush_dns',return_value={'succeeded':True,'exit_code':0})]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.t.cleanup()
 def call(self,action,p=None):return h.handle(self.store,'hosts_reset_'+action,p or {},self.job)
 def prepare(self,ident=None):return self.call('restore_prepare' if ident else 'prepare',{'backup_id':ident})['hosts_reset_plan']
 def apply(self,plan=None):
  plan=plan or self.prepare();restore=plan['operation']=='restore'
  return self.call('restore_apply' if restore else 'apply',dict(expected_sha256=plan['expected_sha256'],plan_digest=plan['plan_digest'],backup_id=plan['backup_id'],confirmation=h.RESTORE_CONFIRM if restore else h.RESET_CONFIRM))
 def test_default_contains_no_active_mappings(self):
  self.assertEqual(hv.parse_hosts(h.DEFAULT_HOSTS)['entries'],[]);self.assertIn(b'#    ::1',h.DEFAULT_HOSTS);self.assertNotIn(b'\n',h.DEFAULT_HOSTS.replace(b'\r\n',b''))
 def test_preview_does_not_write_or_backup_or_flush(self):
  p=self.prepare();self.assertEqual(p['visible_domain_count'],3);self.assertEqual(self.path.read_bytes(),self.before);self.assertFalse(h.backup_root(self.store).exists());h.flush_dns.assert_not_called();self.assertFalse(p['firewall_changed'])
 def test_wrong_confirmation_stops_before_admin_and_write(self):
  for token in ('RESET','reset windows hosts','',None):
   with self.assertRaisesRegex(ValueError,'confirmation'):self.call('apply',{'confirmation':token})
  h.require_admin.assert_not_called();self.assertEqual(self.path.read_bytes(),self.before)
 def test_admin_failure_no_changes(self):
  with patch.object(h,'require_admin',side_effect=ValueError('admin_required')),self.assertRaisesRegex(ValueError,'admin'):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before);self.assertFalse(h.backup_root(self.store).exists())
 def test_stale_content_refused_before_backup(self):
  p=self.prepare();self.path.write_bytes(b'# external\n')
  with self.assertRaisesRegex(ValueError,'stale'):self.apply(p)
  self.assertEqual(self.path.read_bytes(),b'# external\n');self.assertFalse(h.backup_root(self.store).exists())
 def test_tampered_plan_refused(self):
  p=self.prepare();p['plan_digest']='0'*64
  with self.assertRaisesRegex(ValueError,'stale'):self.apply(p)
 def test_backup_exact_bytes_reset_and_dns(self):
  r=self.apply()['hosts_reset_result'];self.assertEqual(self.path.read_bytes(),h.DEFAULT_HOSTS);data,meta=h.get_backup(self.store,r['backup_id']);self.assertEqual(data,self.before);self.assertEqual(meta['sha256'],h.sha(self.before));self.assertTrue(r['hosts_write_verified']);self.assertFalse(r['firewall_changed']);h.flush_dns.assert_called_once();self.assertEqual(len(self.call('list')['hosts_reset_backups']),1)
 def test_backup_failure_aborts_before_write(self):
  with patch.object(h,'write_backup',side_effect=OSError('disk_full')),self.assertRaises(OSError):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before);h.flush_dns.assert_not_called()
 def test_metadata_failure_aborts_before_write(self):
  with patch.object(h,'atomic_json',side_effect=OSError('metadata_failed')),self.assertRaises(OSError):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before);h.flush_dns.assert_not_called()
 def test_backup_verification_failure_aborts(self):
  with patch.object(h,'get_backup',side_effect=ValueError('backup_hash')),self.assertRaises(ValueError):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before)
 def test_restore_exact_and_backs_up_current_first(self):
  first=self.apply()['hosts_reset_result'];r=self.apply(self.prepare(first['backup_id']))['hosts_reset_result'];self.assertEqual(self.path.read_bytes(),self.before);self.assertEqual(h.get_backup(self.store,r['backup_id'])[0],h.DEFAULT_HOSTS);self.assertEqual(len(self.call('list')['hosts_reset_backups']),2)
 def test_restore_preview_stale_when_backup_changed(self):
  ident=self.apply()['hosts_reset_result']['backup_id'];p=self.prepare(ident);(h.backup_root(self.store)/(ident+'.hosts.bak')).write_bytes(b'# tamper')
  with self.assertRaisesRegex(ValueError,'hash'):self.apply(p)
  self.assertEqual(self.path.read_bytes(),h.DEFAULT_HOSTS)
 def test_backup_wrong_machine_refused(self):
  ident=self.apply()['hosts_reset_result']['backup_id']
  with patch.object(h,'machine_id',return_value='other'):
   with self.assertRaisesRegex(ValueError,'computer'):self.prepare(ident)
   self.assertEqual(self.call('list')['hosts_reset_backups'],[])
 def test_backup_id_traversal_refused(self):
  for ident in ('../hosts','C:\\hosts','A'*32,'a'*31,None):
   with self.assertRaisesRegex(ValueError,'id'):h.get_backup(self.store,ident)
 def test_backup_symlink_refused(self):
  ident=self.apply()['hosts_reset_result']['backup_id'];p=h.backup_root(self.store)/(ident+'.hosts.bak');p.unlink();p.symlink_to(self.path)
  with self.assertRaises(ValueError):self.prepare(ident)
 def test_backup_hardlink_refused(self):
  ident=self.apply()['hosts_reset_result']['backup_id'];p=h.backup_root(self.store)/(ident+'.hosts.bak');p.unlink();os.link(self.path,p)
  with self.assertRaisesRegex(ValueError,'single_link'):self.prepare(ident)
 def test_live_hosts_hardlink_refused_no_backup(self):
  os.link(self.path,self.root/'alias')
  with self.assertRaisesRegex(ValueError,'single_link'):self.prepare()
  self.assertEqual(self.path.read_bytes(),self.before)
 def test_live_hosts_symlink_refused(self):
  p=self.root/'linked';p.symlink_to(self.path)
  with patch.object(h,'fixed_hosts',return_value=p),self.assertRaises(ValueError):self.prepare()
 def test_missing_hosts_refused_no_creation(self):
  self.path.unlink()
  with self.assertRaises(FileNotFoundError):self.prepare()
  self.assertFalse(self.path.exists())
 def test_readonly_refused(self):
  p=self.prepare();self.path.chmod(0o444)
  try:
   with self.assertRaisesRegex(ValueError,'readonly'):self.apply(p)
  finally:self.path.chmod(0o644)
  self.assertEqual(self.path.read_bytes(),self.before)
 def test_utf16_backup_restores_exact_encoding(self):
  original=b'\xff\xfe'+'# یادداشت\r\n0.0.0.0 x.example\r\n'.encode('utf-16-le');self.path.write_bytes(original);ident=self.apply()['hosts_reset_result']['backup_id'];self.apply(self.prepare(ident));self.assertEqual(self.path.read_bytes(),original)
 def test_file_size_bound_refused(self):
  self.path.write_bytes(b'#'*65)
  with patch.object(hv,'MAX_BYTES',64),self.assertRaises(ValueError):self.apply()
  self.assertEqual(len(self.path.read_bytes()),65)
 def test_short_write_rolls_back_same_handle(self):
  original=h.write_verified
  def fault(f,data):
   if data==h.DEFAULT_HOSTS:f.seek(0);f.write(b'partial');f.flush();raise OSError('write_failed')
   original(f,data)
  with patch.object(h,'write_verified',side_effect=fault),self.assertRaisesRegex(ValueError,'original_restored'):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before);h.flush_dns.assert_not_called()
 def test_rollback_failure_marked_unknown_backup_retained(self):
  with patch.object(h,'write_verified',side_effect=OSError('disk_fail')),self.assertRaisesRegex(ValueError,'rollback_failed'):self.apply()
  self.assertEqual(len(self.call('list')['hosts_reset_backups']),1)
 def test_dns_failure_does_not_undo_verified_hosts(self):
  with patch.object(h,'flush_dns',return_value={'succeeded':False,'exit_code':1}):r=self.apply()['hosts_reset_result']
  self.assertTrue(r['hosts_write_verified']);self.assertFalse(r['dns_cache_flush']['succeeded']);self.assertEqual(self.path.read_bytes(),h.DEFAULT_HOSTS)
 def test_final_receipt_failure_still_reports_verified_hosts(self):
  original=h.atomic_json
  def fault(path,value):
   if value.get('phase')=='hosts_verified':raise OSError('receipt_full')
   return original(path,value)
  with patch.object(h,'atomic_json',side_effect=fault):r=self.apply()['hosts_reset_result']
  self.assertTrue(r['hosts_write_verified']);self.assertIn('receipt_warning',r)
 def test_noop_still_backup_and_flush_not_rewrite(self):
  self.path.write_bytes(h.DEFAULT_HOSTS)
  with patch.object(h,'write_verified') as w:r=self.apply()['hosts_reset_result']
  w.assert_not_called();self.assertFalse(r['changed']);h.flush_dns.assert_called_once();self.assertEqual(len(self.call('list')['hosts_reset_backups']),1)
 def test_drafts_config_and_old_backups_unchanged(self):
  files=[self.store.root/'hosts-workspace.json',self.store.root/'config-fixture.json'];files[0].write_text('{"rows":["keep"]}');files[1].write_text('{"mode":"keep"}');old=[p.read_bytes() for p in files];self.apply();self.assertEqual([p.read_bytes() for p in files],old)
 def test_locks_share_existing_hosts_operation_lock(self):
  from state import locked
  with locked(self.store.root/'hosts-operation.lock'),self.assertRaises(ValueError):self.apply()
  self.assertEqual(self.path.read_bytes(),self.before)
 def test_dns_command_fixed_no_shell_no_timeout(self):
  # Temporarily unpatch function to test launcher using a fake Windows directory/process.
  original_fn=self.real_flush_dns
  with patch.object(h,'windows_directory',return_value=self.root),patch.object(h.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as run:
   r=original_fn();self.assertTrue(r['succeeded']);args,kw=run.call_args;self.assertEqual(args[0],[str(self.root/'System32/ipconfig.exe'),'/flushdns']);self.assertNotIn('shell',kw);self.assertNotIn('timeout',kw)
 def test_no_firewall_or_audit_commands_in_module(self):
  s=(ROOT/'app/hosts_reset.py').read_text()
  for forbidden in ('netsh','Set-NetFirewall','auditpol','winsock','Remove-NetFirewall','subprocess.Popen','os.system'):self.assertNotIn(forbidden,s)
 def test_desktop_route_and_error_status(self):
  base=self.root/'desktop';jobs=base/'private-state/jobs'/'a';jobs.mkdir(parents=True);request=jobs/'request.json';response=jobs/'response.json';atomic_json(request,dict(action='hosts_reset_apply',payload={}))
  with patch.object(api,'BASE',base):self.assertEqual(api.execute(request,response),1)
  value=json.loads(response.read_text());self.assertIn('unknown_if_write_started',value['hosts_change_status']);self.assertEqual(value['firewall_change_status'],'no_rule_mutation_requested')
 def test_ui_separate_tab_tokens_and_busy_guard(self):
  s=(ROOT/'app/ui-hosts-reset.ps1').read_text('utf-8-sig');main=(ROOT/'app/ui.ps1').read_text('utf-8-sig')
  for text in ('RESET WINDOWS HOSTS','RESTORE HOSTS BACKUP','hosts_reset_prepare','hosts_reset_restore_prepare','ConfirmText','Nested-Tab $hostSections','Set-HostsResetControls'):self.assertIn(text,s)
  for text in ('Set-HostsResetControls $Busy','Confirm-HostsResetPlan $hostsResetPrepared','Accept-HostsResetResult $r',"'ui-hosts-reset.ps1'"):self.assertIn(text,main)
  self.assertNotIn('$menu',s);self.assertNotIn("BeginOp 'native_",s)

if __name__=='__main__':unittest.main()
