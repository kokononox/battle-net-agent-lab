import copy,contextlib,hashlib,json,pathlib,sys,tempfile,types,unittest,zipfile
from unittest.mock import patch,Mock
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'app')]
import hosts_edit as he,hosts_view as hv,hosts_ops as ho,live_ops as lo,desktop_cli as api
from policy import PolicyError,program_id,windows_path
from state import Store,atomic_json

def capture(cid='a'*32):
 p=dict(path=r'C:\Apps\Game.exe',sha256='c'*64,id=program_id(r'C:\Apps\Game.exe'),enabled=True)
 t='2026-10-24T12:00:00Z'
 row=dict(record_id='b'*32,program_id=p['id'],program_path=p['path'],pid=99,process_start_ticks='123456',protocol='TCP',local_ip='10.0.0.2',local_port=40000,remote_ip='8.8.8.8',remote_port=443,first_seen_utc=t,last_seen_utc=t,samples=3,states={'Established':3},presence='present')
 return dict(schema='unified-live-monitor-1',capture_id=cid,programs=[p],endpoints=[row],revision=4,status='finished',ready=True,last_sample_ok=True,started_utc=t,published_utc=t,ended_utc=t,successful_samples=3,query_errors=0,publication_errors=0,unreadable_process_instances=0,truncated=False,firewall_changed=False,packet_drop_verified=False)
class RestoredTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.store=Store(self.root/'private',lambda p:dict(path=windows_path(p),sha256='c'*64));self.hosts=self.root/'hosts';self.before=b'# keep\r\n127.0.0.1 localhost\r\n9.9.9.9 a.example alias.example # retained comment\r\n';self.hosts.write_bytes(self.before);self.job=self.root/'job';self.job.mkdir()
 def tearDown(self):self.tmp.cleanup()
 def hp(self,**kw):return dict(domains='a.example\nb.example',operation='sink',**kw)
 def read_patch(self):return patch.object(he,'standard_path',return_value=self.hosts)
 def test_hosts_prepare_does_not_write(self):
  with self.read_patch():p=ho.handle(self.store,'hosts_prepare',self.hp(),self.job)['hosts_plan']
  self.assertEqual(self.hosts.read_bytes(),self.before);self.assertTrue(p['system_wide']);self.assertTrue(p['whitelist_cannot_override_hosts']);self.assertFalse(p['blocking_verified']);self.assertFalse((self.store.root/'hosts-backups').exists())
 def test_hosts_domain_validation(self):
  for name in ('https://a.example/x','*.example','a.example/x','a.example b.example','localhost','127.0.0.1','a.example\tother','a..example','-a.example'):
   with self.subTest(name=name),self.assertRaises(ValueError):ho.changes_from(dict(domains=name,operation='sink'))
 def test_hosts_idna_case_dedup(self):
  c=ho.changes_from(dict(domains='EXAMPLE.COM.\nexample.com\nمثال.com',operation='sink'));self.assertEqual(len(c),2);self.assertEqual(c[0]['domain'],'example.com');self.assertTrue(c[1]['domain'].startswith('xn--'))
 def test_hosts_limit_empty_unknown_operation(self):
  for p in ({},dict(domains='',operation='sink'),dict(domains='a.example',operation='custom'),dict(domains='\n'.join(f'{x}.example' for x in range(501)),operation='sink')):
   with self.assertRaises(ValueError):ho.changes_from(p)
 def test_hosts_two_sink_addresses(self):
  out,changes=he.prepare(self.before,ho.changes_from(self.hp()));parsed=hv.parse_hosts(out);r=next(r for r in parsed['entries'] if r['domain']=='a.example');self.assertEqual(set(r['addresses']),{'0.0.0.0','::'});self.assertIn(b'alias.example # retained comment',out);self.assertIn(b'127.0.0.1 localhost',out)
 def test_hosts_remove_preserves_other_alias(self):
  out,_=he.prepare(self.before,ho.changes_from(dict(domains='a.example',operation='remove')));self.assertNotIn(b' a.example',out);self.assertIn(b'alias.example # retained comment',out)
 def test_hosts_preserves_utf16_and_comments(self):
  text='# یادداشت\r\n127.0.0.1 localhost\r\n';data=b'\xff\xfe'+text.encode('utf-16-le');out,_=he.prepare(data,ho.changes_from(dict(domains='a.example',operation='sink')));self.assertTrue(out.startswith(b'\xff\xfe'));self.assertIn(text,out.decode('utf-16'));self.assertIn('a.example',out.decode('utf-16'))
 def test_hosts_cp1252_unchanged_comments(self):
  b=b'# caf\xe9\n127.0.0.1 localhost\n';out,_=he.prepare(b,ho.changes_from(self.hp()));self.assertTrue(out.startswith(b))
 def test_hosts_lowlevel_consent(self):
  with self.assertRaisesRegex(ValueError,'consent'):he.apply_hosts(self.store.root,{})
 def test_hosts_lowlevel_hash(self):
  with self.read_patch(),self.assertRaisesRegex(ValueError,'changed_externally'):he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256='0'*64,changes=ho.changes_from(self.hp())))
  self.assertEqual(self.hosts.read_bytes(),self.before)
 def test_hosts_verified_backup_readback_fixture(self):
  with self.read_patch():r=he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256=ho.sha(self.before),changes=ho.changes_from(self.hp())))
  self.assertEqual((self.store.root/'hosts-backups'/r['backup_filename']).read_bytes(),self.before);self.assertEqual(ho.sha(self.hosts.read_bytes()),r['after_sha256']);self.assertFalse(r['dns_cache_flushed']);self.assertFalse(r['blocking_verified'])
 def test_hosts_noop_no_backup(self):
  with self.read_patch():r=he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256=ho.sha(self.before),changes=ho.changes_from(dict(domains='missing.example',operation='remove'))))
  self.assertFalse(r['changed']);self.assertFalse(r['backup_created'])
 def test_hosts_protected_name_lowlevel(self):
  with self.assertRaisesRegex(ValueError,'protected'):he.prepare(self.before,[dict(domain='localhost',action='remove')])
 def test_hosts_exclusive_fixture_lock(self):
  with he.locked_file(self.hosts):
   with self.assertRaises(OSError):
    with he.locked_file(self.hosts):pass
 def test_hosts_symlink_and_hardlink_refused_fixture(self):
  import os
  link=self.root/'link';link.symlink_to(self.hosts)
  with self.assertRaises(OSError):
   with he.locked_file(link):pass
  link.unlink();os.link(self.hosts,link)
  with self.assertRaisesRegex(ValueError,'single_link'):
   with he.locked_file(self.hosts):pass
 def test_hosts_backup_failure_before_write(self):
  with self.read_patch(),patch.object(he.uuid,'uuid4',return_value=types.SimpleNamespace(hex='fixture')):
   d=self.store.root/'hosts-backups';d.mkdir();(d/'fixture.hosts.bak').write_bytes(b'existing')
   with self.assertRaises(FileExistsError):he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256=ho.sha(self.before),changes=ho.changes_from(self.hp())))
  self.assertEqual(self.hosts.read_bytes(),self.before)
 def test_hosts_write_failure_rolls_back_same_handle(self):
  @contextlib.contextmanager
  def fault(path):
   with he.locked_file_original(path) as f:
    class Wrapper:
     def __getattr__(self,k):return getattr(f,k)
     def write(self,data):
      if data!=self.before:
       f.write(data[:5]);raise OSError('fixture partial write')
      return f.write(data)
    w=Wrapper();w.before=self.before;yield w
  with self.read_patch(),patch.object(he,'locked_file_original',he.locked_file,create=True),patch.object(he,'locked_file',fault):
   with self.assertRaisesRegex(ValueError,'original_restored'):he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256=ho.sha(self.before),changes=ho.changes_from(self.hp())))
  self.assertEqual(self.hosts.read_bytes(),self.before)
 def test_hosts_rollback_readback_failure_honest(self):
  @contextlib.contextmanager
  def fault(path):
   with he.locked_file_original(path) as f:
    class Wrapper:
     def __getattr__(self,k):return getattr(f,k)
     def write(self,data):f.write(data[:3]);raise OSError('fixture always broken')
    yield Wrapper()
  with self.read_patch(),patch.object(he,'locked_file_original',he.locked_file,create=True),patch.object(he,'locked_file',fault):
   with self.assertRaisesRegex(ValueError,'rollback_failed'):he.apply_hosts(self.store.root,dict(hosts_edit_consent=True,expected_sha256=ho.sha(self.before),changes=ho.changes_from(self.hp())))
  self.assertTrue(any((self.store.root/'hosts-backups').iterdir()))
 def test_hosts_preview_digest_change_refused(self):
  with self.read_patch():p=ho.handle(self.store,'hosts_prepare',self.hp(),self.job)['hosts_plan']
  with self.read_patch(),patch.object(he,'apply_hosts') as fn,self.assertRaisesRegex(ValueError,'stale'):
   ho.handle(self.store,'hosts_apply',dict(self.hp(),expected_sha256=p['expected_sha256'],plan_digest='0'*64,confirmation=ho.CONFIRM),self.job)
  fn.assert_not_called()
 def test_hosts_external_change_refused(self):
  with self.read_patch():p=ho.handle(self.store,'hosts_prepare',self.hp(),self.job)['hosts_plan']
  self.hosts.write_bytes(self.before+b'# external\n')
  with self.read_patch(),patch.object(he,'apply_hosts') as fn,self.assertRaisesRegex(ValueError,'stale'):
   ho.handle(self.store,'hosts_apply',dict(self.hp(),expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest'],confirmation=ho.CONFIRM),self.job)
  fn.assert_not_called()
 def test_hosts_confirmation_before_any_read(self):
  with patch.object(ho,'read_data') as fn,self.assertRaisesRegex(ValueError,'confirmation'):ho.handle(self.store,'hosts_apply',self.hp(),self.job)
  fn.assert_not_called()
 def test_hosts_nonwindows_adapter_write_refused(self):
  with self.read_patch():p=ho.handle(self.store,'hosts_prepare',self.hp(),self.job)['hosts_plan']
  with self.read_patch(),patch.object(he,'apply_hosts') as fn,self.assertRaisesRegex(ValueError,'Windows'):
   ho.handle(self.store,'hosts_apply',dict(self.hp(),expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest'],confirmation=ho.CONFIRM),self.job)
  fn.assert_not_called()
 def test_hosts_adapter_explicit_admin_fixture(self):
  import ctypes
  with self.read_patch():p=ho.handle(self.store,'hosts_prepare',self.hp(),self.job)['hosts_plan']
  q=dict(self.hp(),expected_sha256=p['expected_sha256'],plan_digest=p['plan_digest'],confirmation=ho.CONFIRM)
  win=types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda:False))
  with self.read_patch(),patch.object(ho,'os',types.SimpleNamespace(name='nt')),patch.object(ctypes,'windll',win,create=True),patch.object(he,'apply_hosts') as fn,self.assertRaisesRegex(ValueError,'administrator'):ho.handle(self.store,'hosts_apply',q,self.job)
  fn.assert_not_called()
  win.shell32.IsUserAnAdmin=lambda:True
  with self.read_patch(),patch.object(ho,'os',types.SimpleNamespace(name='nt')),patch.object(ctypes,'windll',win,create=True):r=ho.handle(self.store,'hosts_apply',q,self.job)
  self.assertTrue(r['hosts_result']['changed']);self.assertFalse(r['firewall_changed'])
 def test_hosts_no_arbitrary_path_or_addresses(self):
  p=self.hp(path='/arbitrary',addresses=['8.8.8.8']);c=ho.changes_from(p);self.assertEqual(c[0]['addresses'],['0.0.0.0','::'])
 def test_hosts_error_api_unknown_not_unchanged(self):
  folder=self.root/'private-state/jobs/fixture';folder.mkdir(parents=True);req=folder/'request.json';out=folder/'response.json';req.write_text(json.dumps(dict(action='hosts_apply',payload={})))
  with patch.object(api,'BASE',self.root),patch.object(ho,'handle',side_effect=ValueError('hosts_write_and_rollback_failed')):self.assertEqual(api.execute(req,out),1)
  r=json.loads(out.read_text());self.assertIn('unknown_if_write_started',r['hosts_change_status']);self.assertNotIn('hosts_changed',r);self.assertFalse(r['ok'])
 def test_capture_valid_archive_history(self):
  a=lo.Archive(self.store.root);c=capture();a.save(c);self.assertEqual(a.load(c['capture_id']),c);self.assertEqual(a.history()['captures'][0]['records'],1)
 def test_capture_ids_do_not_allow_traversal(self):
  a=lo.Archive(self.store.root)
  for v in ('../settings',None,'A'*32,'a'*31):
   with self.assertRaises(PolicyError):a.load(v)
 def test_capture_no_overwrite_or_unfinished(self):
  a=lo.Archive(self.store.root);c=capture();a.save(c)
  with self.assertRaisesRegex(PolicyError,'exists'):a.save(c)
  c['capture_id']='d'*32;c['status']='recording'
  with self.assertRaisesRegex(PolicyError,'final_only'):a.save(c)
 def test_capture_wrong_path_identity(self):
  c=capture();c['endpoints'][0]['program_path']=r'C:\Other\Game.exe'
  with self.assertRaisesRegex(PolicyError,'identity'):lo.validate(c)
 def test_capture_wrong_program_id(self):
  c=capture();c['programs'][0]['id']='1'*24
  with self.assertRaisesRegex(PolicyError,'path_id'):lo.validate(c)
 def test_capture_wrong_file_identity(self):
  a=lo.Archive(self.store.root);c=capture();atomic_json(a.path('d'*32),c)
  with self.assertRaisesRegex(PolicyError,'stored_identity'):a.load('d'*32)
 def test_capture_bad_fields(self):
  for key,value in (('remote_port',65536),('local_ip','garbage'),('pid',0),('samples',True),('presence','blocked'),('protocol','UDP'),('process_start_ticks','bad')):
   c=capture();c['endpoints'][0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):lo.validate(c)
 def test_capture_duplicate_record_refused(self):
  c=capture();c['endpoints'].append(copy.deepcopy(c['endpoints'][0]))
  with self.assertRaisesRegex(PolicyError,'record'):lo.validate(c)
 def test_capture_bad_scope(self):
  c=capture();c['packet_drop_verified']=True
  with self.assertRaisesRegex(PolicyError,'scope'):lo.validate(c)
 def test_history_corrupt_file_reported(self):
  a=lo.Archive(self.store.root);a.path('a'*32).write_text('{}');self.assertEqual(a.history()['invalid_or_unreadable'],1)
 def test_history_bounded_200_no_delete(self):
  a=lo.Archive(self.store.root)
  for i in range(201):c=capture(f'{i:032x}');a.save(c)
  h=a.history();self.assertEqual(len(h['captures']),200);self.assertEqual(h['older_not_listed'],1);self.assertEqual(len(list(a.root.glob('*.json'))),201)
 def test_export_private_warning_and_paths_removed(self):
  a=lo.Archive(self.store.root);c=capture();a.save(c);r=lo.handle(self.store,'monitor_export',dict(capture_id=c['capture_id']),self.job)
  with zipfile.ZipFile(r['export_file']) as z:
   data=json.loads(z.read('capture.json'));self.assertNotIn('path',data['programs'][0]);self.assertNotIn('program_path',data['endpoints'][0]);self.assertIn('8.8.8.8',z.read('README.txt').decode())
  self.assertFalse(r['firewall_changed'])
 def test_stage_same_exe_config_only(self):
  s=self.store.register([r'C:\Apps\Game.exe',r'C:\Other\Game.exe'],0);c=capture();lo.Archive(self.store.root).save(c)
  r=lo.handle(self.store,'monitor_stage',dict(capture_id=c['capture_id'],record_id=c['endpoints'][0]['record_id'],generation=1),self.job);e=r['state']['config']['blacklist'][0];self.assertEqual(e['program_ids'],[c['programs'][0]['id']]);self.assertEqual(len(r['state']['config']['programs']),2);self.assertFalse(r['firewall_changed'])
 def test_stage_stale_generation_refused(self):
  self.store.register([r'C:\Apps\Game.exe'],0);c=capture();lo.Archive(self.store.root).save(c)
  with self.assertRaisesRegex(PolicyError,'config_changed'):lo.handle(self.store,'monitor_stage',dict(capture_id=c['capture_id'],record_id='b'*32,generation=0),self.job)
 def test_stage_hash_changed_refused(self):
  self.store.register([r'C:\Apps\Game.exe'],0);c=capture();c['programs'][0]['sha256']='d'*64;lo.Archive(self.store.root).save(c)
  with self.assertRaisesRegex(PolicyError,'program_changed'):lo.handle(self.store,'monitor_stage',dict(capture_id=c['capture_id'],record_id='b'*32,generation=1),self.job)
 def test_monitor_duration_rejects_bad(self):
  for n in (True,-1,1,999,'60'):
   with self.assertRaisesRegex(PolicyError,'duration'):lo.record(self.store,dict(seconds=n),self.job)
 def test_monitor_supported_duration_no_windows_gate(self):
  for n in lo.DURATIONS:
   with self.assertRaisesRegex(PolicyError,'requires_windows'):lo.record(self.store,dict(seconds=n),self.job)
 def test_no_native_dependency_in_readonly_monitor(self):
  text=(ROOT/'app/live.ps1').read_text('utf-8-sig');self.assertIn('Get-NetTCPConnection',text);self.assertIn('observe-core.ps1',text)
  for token in ('New-NetFirewallRule','Set-NetFirewallRule','Remove-NetFirewallRule','Set-ExecutionPolicy','wevtutil','Stop-Process','Resolve-DnsName'):self.assertNotIn(token,text)
 def test_ui_scope_and_popup_boundaries(self):
  text=(ROOT/'app/ui.ps1').read_text('utf-8-sig')+(ROOT/'app/ui-evidence.ps1').read_text('utf-8-sig')
  for token in ('hosts_prepare','hosts_apply','I ACCEPT SYSTEM WIDE HOSTS CHANGES','preview_stale' if False else 'plan_digest','monitor_record','Render-Popup','pause.Checked','follow.Checked','flash.Checked','Get-LivePulse','FileShare]::Delete','Prefill-Observed','monitor_export','interrupted'):
   self.assertIn(token,text)
  for token in ('DoEvents','.Kill(','Stop-Process','ExecutionPolicy Bypass'):self.assertNotIn(token,text)
 def test_additional_range_risk_required(self):
  import desktop_ops as ops
  self.store.register([r'C:\Apps\Game.exe'],0);pid=self.store.read()['config']['programs'][0]['id'];self.store.add_blacklist([pid],'8.8.8.0/24','TCP',443,1)
  p=ops.handle(self.store,'native_prepare',{'generation':2})['preparation'];self.assertEqual(p['additional_risks']['network_ranges'][0]['address_count'],'256')
  q=dict(generation=2,plan_digest=p['plan_digest'],confirmation='I ACCEPT LAB NETWORK CHANGES')
  with patch.object(ops,'native_result',return_value={'native_ok':True}) as fn:
   with self.assertRaisesRegex(PolicyError,'range_requires'):ops.handle(self.store,'native_apply_blacklist',q)
   fn.assert_not_called();q['range_confirmation']='I ACCEPT NETWORK RANGE RISK';self.assertTrue(ops.handle(self.store,'native_apply_blacklist',q)['native_ok']);fn.assert_called_once()
 def test_additional_login_risk_required_exact_protocol_port(self):
  from risk_confirmations import risks,require,LOGIN_TEXT
  from policy import blacklist_entry
  self.store.register([r'C:\Apps\Game.exe'],0);c=self.store.read()['config'];pid=c['programs'][0]['id']
  for proto,port,needed in (('TCP',3724,True),('UDP',3724,False),('TCP',443,False)):
   c['blacklist']=[blacklist_entry([pid],'37.244.29.11',proto,port)];self.assertEqual(bool(risks(c)['known_login_endpoint_entry_ids']),needed)
   if needed:
    with self.assertRaisesRegex(PolicyError,'login_endpoint'):require(c,{})
    require(c,{'login_confirmation':LOGIN_TEXT})
 def test_additional_risks_disabled_program_not_active(self):
  from risk_confirmations import risks
  from policy import blacklist_entry
  self.store.register([r'C:\Apps\Game.exe'],0);c=self.store.read()['config'];pid=c['programs'][0]['id'];c['blacklist']=[blacklist_entry([pid],'8.8.8.0/24','TCP',443)];c['programs'][0]['enabled']=False
  self.assertFalse(risks(c)['network_ranges'])
if __name__=='__main__':unittest.main()
