import pathlib,sys,tempfile,unittest,uuid,copy,json
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
import workspace_ops as w
from state import Store
from policy import PolicyError,windows_path

def host(name='telemetry.example',operation='sink'):
 return dict(id=uuid.uuid4().hex,domain=name,operation=operation)
class WorkspaceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.calls=[]
  def inspect(p):self.calls.append(p);return dict(path=windows_path(p),sha256='a'*64)
  self.store=Store(self.root/'private',inspect);self.store.read();self.job=self.root/'job';self.job.mkdir()
 def tearDown(self):self.tmp.cleanup()
 def call(self,a,p=None):return w.handle(self.store,'workspace_'+a,p or {},self.job)
 def test_missing_local_hosts_read_does_not_create_draft(self):
  r=self.call('hosts_load');self.assertEqual(r['workspace_hosts']['revision'],0);self.assertFalse(w.host_file(self.store).exists());self.assertFalse(r['hosts_changed'])
 def test_hosts_save_and_reload_local_only(self):
  row=host('TELEMETRY.EXAMPLE.');r=self.call('hosts_save',dict(revision=0,rows=[row]));self.assertTrue(r['saved_locally_only']);self.assertFalse(r['hosts_changed']);self.assertEqual(self.call('hosts_load')['workspace_hosts']['rows'][0]['domain'],'telemetry.example')
 def test_hosts_revision_conflict_preserves_file(self):
  self.call('hosts_save',dict(revision=0,rows=[host()]));before=w.host_file(self.store).read_bytes()
  with self.assertRaisesRegex(PolicyError,'changed'):self.call('hosts_save',dict(revision=0,rows=[]))
  self.assertEqual(before,w.host_file(self.store).read_bytes())
 def test_local_empty_save_does_not_remove_actual_hosts(self):
  self.call('hosts_save',dict(revision=0,rows=[host()]));r=self.call('hosts_save',dict(revision=1,rows=[]));self.assertEqual(r['workspace_hosts']['rows'],[])
 def test_local_edit_delete_saved_rows(self):
  a,b=host('a.example'),host('b.example');self.call('hosts_save',dict(revision=0,rows=[a,b]));a['domain']='renamed.example';a['operation']='remove';r=self.call('hosts_save',dict(revision=1,rows=[a]));self.assertEqual(r['workspace_hosts']['rows'],[a])
 def test_duplicate_domain_case_and_different_operations_rejected(self):
  with self.assertRaisesRegex(PolicyError,'duplicate'):w.clean_hosts([host('a.example'),host('A.EXAMPLE.','remove')])
 def test_invalid_row_schema_and_unsupported_mapping(self):
  for bad in ({**host(),'address':'8.8.8.8'},dict(id='bad',domain='a.example',operation='sink'),host('a.example','allow')):
   with self.assertRaises((PolicyError,ValueError)):w.clean_hosts([bad])
 def test_draft_limit_and_duplicate_ids(self):
  a=host()
  with self.assertRaises(PolicyError):w.clean_hosts([a,{**a,'domain':'b.example'}])
  with self.assertRaisesRegex(PolicyError,'limit'):w.clean_hosts([host(f'a{i}.example') for i in range(501)])
 def test_no_URL_wildcard_ip_whitespace_or_protected_system_names(self):
  for name in ('https://a.example','*.a.example','127.0.0.1','localhost','a.example\nb.example','a.example b.example','wpad'):
   with self.subTest(name=name),self.assertRaises((ValueError,PolicyError)):w.clean_hosts([host(name)])
 def test_hostnames_are_validated_once_per_operation_group(self):
  with patch.object(w.ho,'changes_from',wraps=w.ho.changes_from) as f:
   w.clean_hosts([host(f'a{i}.example', 'sink' if i%2 else 'remove') for i in range(50)]);self.assertEqual(f.call_count,2)
 def test_batch_plan_mixed_changes_preserves_alias_and_comments(self):
  data=b'# comment\r\n1.1.1.1 old.example alias.example # inline\r\n'
  p=w.hosts_batch_plan(data,[host('old.example','remove'),host('new.example')]);self.assertTrue(p['system_wide']);self.assertFalse(p['per_EXE']);self.assertTrue(p['whitelist_cannot_override_hosts']);self.assertFalse(p['blocking_verified']);self.assertEqual(len(p['changes']),2)
  after,_=w.he.prepare(data,p['changes']);self.assertIn(b'alias.example',after);self.assertIn(b'# comment',after);self.assertNotIn(b'old.example',after);self.assertIn(b'new.example',after)
 def test_batch_digest_deterministic_but_change_invalidates_it(self):
  data=b'127.0.0.1 localhost\n';a=w.hosts_batch_plan(data,[host()]);b=w.hosts_batch_plan(data,[host()]);self.assertEqual(a['plan_digest'],b['plan_digest']);self.assertNotEqual(a['plan_digest'],w.hosts_batch_plan(data,[host('b.example')])['plan_digest'])
 def test_empty_plan_refuses_instead_of_resetting_actual_file(self):
  with self.assertRaisesRegex(PolicyError,'empty'):w.hosts_batch_plan(b'',[])
 def test_truncated_actual_view_rejected(self):
  with patch.object(w.hv,'parse_hosts',return_value=dict(truncated=True)):
   with self.assertRaisesRegex(PolicyError,'truncated'):w.hosts_batch_plan(b'', [host()])
 def test_prepare_is_read_only_and_returns_fixed_adapter_plan(self):
  with patch.object(w.ho,'read_data',return_value=(b'# keep\n',{})),patch.object(w.he,'apply_hosts') as apply:
   r=self.call('hosts_prepare',dict(rows=[host()]));self.assertIn('hosts_plan',r);apply.assert_not_called()
 def test_apply_requires_exact_confirmation_before_reading(self):
  with patch.object(w.ho,'read_data') as read:
   with self.assertRaisesRegex(PolicyError,'confirmation'):self.call('hosts_apply',dict(rows=[host()],confirmation='yes'))
   read.assert_not_called()
 def test_stale_apply_never_reaches_writer(self):
  with patch.object(w.ho,'read_data',return_value=(b'',{})),patch.object(w.he,'apply_hosts') as write:
   with self.assertRaisesRegex(PolicyError,'stale'):self.call('hosts_apply',dict(rows=[host()],confirmation=w.ho.CONFIRM,expected_sha256='bad',plan_digest='bad'))
   write.assert_not_called()
 def test_linux_cannot_apply_even_with_valid_digest(self):
  rows=[host()];p=w.hosts_batch_plan(b'',rows)
  with patch.object(w.ho,'read_data',return_value=(b'',{})),patch.object(w.he,'apply_hosts') as write:
   with self.assertRaisesRegex(PolicyError,'Windows'):self.call('hosts_apply',dict(rows=rows,confirmation=w.ho.CONFIRM,expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest']))
   write.assert_not_called()
 def test_stored_draft_invalid_revision_rejected_without_repair(self):
  path=w.host_file(self.store);path.write_text(json.dumps(dict(schema='unified-hosts-draft-1',revision=True,rows=[])));before=path.read_bytes()
  with self.assertRaisesRegex(PolicyError,'schema'):self.call('hosts_load')
  self.assertEqual(path.read_bytes(),before)
 def test_symlink_draft_not_followed(self):
  target=self.root/'outside.json';target.write_text('{}');w.host_file(self.store).symlink_to(target)
  with self.assertRaises((PolicyError,ValueError)):self.call('hosts_load')
  self.assertEqual(target.read_text(),'{}')
 def test_admin_denied_batch_apply_never_reaches_writer(self):
  from types import SimpleNamespace as NS
  import ctypes
  rows=[host()];p=w.hosts_batch_plan(b'',rows)
  with patch.object(w.ho,'read_data',return_value=(b'',{})),patch.object(w,'os',NS(name='nt')),patch.object(ctypes,'windll',NS(shell32=NS(IsUserAnAdmin=lambda:False)),create=True),patch.object(w.he,'apply_hosts') as write:
   with self.assertRaisesRegex(PolicyError,'administrator'):self.call('hosts_apply',dict(rows=rows,confirmation=w.ho.CONFIRM,expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest']))
   write.assert_not_called()
 def test_admin_consented_matching_plan_delegates_only_validated_changes(self):
  from types import SimpleNamespace as NS
  import ctypes
  rows=[host()];p=w.hosts_batch_plan(b'',rows)
  with patch.object(w.ho,'read_data',return_value=(b'',{})),patch.object(w,'os',NS(name='nt')),patch.object(ctypes,'windll',NS(shell32=NS(IsUserAnAdmin=lambda:True)),create=True),patch.object(w.he,'apply_hosts',return_value=dict(fake=True)) as write:
   r=self.call('hosts_apply',dict(rows=rows,confirmation=w.ho.CONFIRM,expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest'],path='ignored'))
   args=write.call_args.args;self.assertEqual(args[0],self.store.root);self.assertEqual(args[1],dict(hosts_edit_consent=True,expected_sha256=p['expected_sha256'],changes=p['changes']));self.assertFalse(r['blocking_verified'])
 def prepare_program(self):
  s=self.store.register([r'C:\Apps\Game.exe'],0);return s['config']['programs'][0]['id']
 def row(self,pid,**kw):return dict(program_ids=[pid],target='8.8.8.8',protocol='TCP',port=443,source_path='',**kw)
 def test_black_save_only_configuration_no_registration(self):
  pid=self.prepare_program();n=len(self.calls);r=self.call('blacklist_save',dict(generation=1,rows=[self.row(pid)]));self.assertEqual(len(self.calls),n);self.assertTrue(r['saved_only']);self.assertFalse(r['firewall_changed']);self.assertFalse(r['hosts_changed']);self.assertEqual(len(r['state']['config']['blacklist']),1)
 def test_black_save_empty_removes_settings_only(self):
  pid=self.prepare_program();self.call('blacklist_save',dict(generation=1,rows=[self.row(pid)]));r=self.call('blacklist_save',dict(generation=2,rows=[]));self.assertEqual(r['state']['config']['blacklist'],[])
 def test_observed_path_must_match_single_registered_EXE(self):
  pid=self.prepare_program();r=self.row(pid);r['source_path']=r'C:\Apps\Other.exe';before=self.store.file.read_bytes()
  with self.assertRaisesRegex(PolicyError,'observed_EXE'):self.call('blacklist_save',dict(generation=1,rows=[r]))
  self.assertEqual(before,self.store.file.read_bytes())
 def test_observed_path_casefold_matching_permitted(self):
  pid=self.prepare_program();r=self.row(pid);r['source_path']=r'c:\APPS\game.exe';self.call('blacklist_save',dict(generation=1,rows=[r]))
 def test_incomplete_rows_atomic_no_guessing_transport_or_scope(self):
  pid=self.prepare_program()
  for changes in (dict(port=0),dict(protocol=''),dict(program_ids=[]),dict(target='domain.example'),dict(target='127.0.0.1')):
   r=self.row(pid);r.update(changes);before=self.store.file.read_bytes()
   with self.subTest(changes=changes),self.assertRaises((PolicyError,ValueError)):self.call('blacklist_save',dict(generation=1,rows=[self.row(pid),r]))
   self.assertEqual(before,self.store.file.read_bytes())
 def test_unknown_program_rejected_atomic(self):
  pid=self.prepare_program();before=self.store.file.read_bytes()
  with self.assertRaises(PolicyError):self.call('blacklist_save',dict(generation=1,rows=[self.row('f'*24)]))
  self.assertEqual(before,self.store.file.read_bytes())
 def test_stale_black_generation_rejected(self):
  pid=self.prepare_program()
  with self.assertRaisesRegex(PolicyError,'config_changed'):self.call('blacklist_save',dict(generation=0,rows=[self.row(pid)]))
 def test_black_duplicates_dedup_and_limit(self):
  pid=self.prepare_program();r=self.call('blacklist_save',dict(generation=1,rows=[self.row(pid)]*2));self.assertEqual(len(r['state']['config']['blacklist']),1)
  with self.assertRaisesRegex(PolicyError,'limit'):self.call('blacklist_save',dict(generation=2,rows=[self.row(pid)]*257))
 def test_range_prefix_extent(self):
  r=self.call('range_preview',dict(mode='pattern',value='2.19',protocol='TCP',port=443));p=r['range_preview'];self.assertEqual((p['first_ip'],p['last_ip'],p['address_count']),('2.19.0.0','2.19.255.255','65536'));self.assertFalse(r['firewall_changed']);self.assertFalse(p['applied'])
 def test_range_between_exact_extent(self):
  p=self.call('range_preview',dict(mode='between',value='8.8.8.8',last='8.8.8.12',protocol='UDP',port=53))['range_preview'];self.assertEqual(p['address_count'],'5');self.assertGreater(p['rule_count'],1)
 def test_range_CIDR_hostbits_normalized_in_preview(self):
  p=self.call('range_preview',dict(mode='cidr',value='8.8.8.9/24',protocol='TCP',port=443))['range_preview'];self.assertEqual(p['first_ip'],'8.8.8.0');self.assertEqual(p['last_ip'],'8.8.8.255')
 def test_range_public_IPv6_supported(self):
  p=self.call('range_preview',dict(mode='cidr',value='2606:4700:4700::1111/128',protocol='TCP',port=443))['range_preview'];self.assertEqual(p['address_count'],'1')
 def test_range_special_use_overlap_rejected(self):
  for value in ('10.*','127.*','0.*','*','192.168.*'):
   with self.subTest(value=value),self.assertRaises(ValueError):self.call('range_preview',dict(mode='pattern',value=value,protocol='TCP',port=443))
 def test_range_invalid_wildcard_order_port_or_address_family(self):
  for payload in (dict(mode='pattern',value='8.*.8.*',port=443),dict(mode='pattern',value='008.8',port=443),dict(mode='pattern',value='2.19',port=0),dict(mode='between',value='8.8.8.8',last='1.1.1.1',port=443),dict(mode='between',value='8.8.8.8',last='2606:4700::1',port=443)):
   with self.assertRaises(ValueError):self.call('range_preview',dict(protocol='TCP',**payload))
 def test_UI_routes_have_distinct_local_save_and_preview(self):
  s=(ROOT/'app/ui-workspace.ps1').read_text('utf-8-sig');ui=(ROOT/'app/ui.ps1').read_text('utf-8-sig')
  for x in ('workspace_hosts_save','workspace_blacklist_save','workspace_range_preview','workspace_hosts_prepare','ipDraftGrid','blackDomainGrid','hostDraftGrid','actualEdit','actualDelete'):self.assertIn(x,s)
  self.assertIn("BeginOp 'workspace_hosts_apply'",ui);self.assertIn("I ACCEPT SYSTEM WIDE HOSTS CHANGES",ui);self.assertIn('if($script:ipDirty)',ui)
 def test_navigation_tools_detached_not_disposed(self):
  s=(ROOT/'app/ui-workspace.ps1').read_text('utf-8-sig');self.assertIn('$script:desktopNavigationPanel.Controls.Remove($entry.tools)',s);self.assertIn('$entry.tools.Visible=$false',s);self.assertNotIn('$entry.tools.Dispose',s)
 def test_desktop_error_classifies_hosts_write_as_unknown(self):
  s=(ROOT/'app/desktop_cli.py').read_text();self.assertIn("('hosts_apply','workspace_hosts_apply')",s)
if __name__=='__main__':unittest.main()
