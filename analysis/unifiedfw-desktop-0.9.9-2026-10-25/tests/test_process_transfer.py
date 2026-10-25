import pathlib,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from state import Store
from cli import handle
from policy import PolicyError,windows_path
class ProcessTransferTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.calls=[];self.bad=None
  def inspect(p):
   self.calls.append(p)
   if p==self.bad:raise PolicyError('fake_missing_EXE')
   return dict(path=windows_path(p),sha256='a'*64)
  self.store=Store(self.root/'private',inspect);self.job=self.root/'job';self.job.mkdir();self.s=(ROOT/'app/ui-transfer.ps1').read_text('utf-8-sig')
 def tearDown(self):self.tmp.cleanup()
 def test_uses_existing_register_action_and_marks_navigation(self):
  self.assertIn("BeginOp 'register'",self.s);self.assertIn('$script:job.process_transfer=$true',self.s);self.assertNotIn('store.register',self.s)
 def test_both_windows_and_context_menu_have_explicit_transfer(self):
  for x in ('$monitorTools $transferPrograms','$popupTools $popupTransferPrograms', '$mainLiveTabs.SelectedTab', '$popupLiveTabs.SelectedTab', '$script:observedMenus'):self.assertIn(x,self.s)
 def test_no_native_or_hosts_or_IP_destination_mutation(self):
  for x in ("BeginOp 'native_", "BeginOp 'hosts_", "BeginOp 'add_blacklist'", "BeginOp 'configure'",'Set-NetFirewall','Stop-Process','taskkill','-Force'):self.assertNotIn(x,self.s)
  prefill=(ROOT/'app/ui-context.ps1').read_text('utf-8-sig');self.assertNotIn('BeginOp',prefill)
 def test_pending_runs_only_after_disposal_and_has_success_flag(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertIn('$operationSucceeded=$false',s);self.assertIn('$operationSucceeded=$true',s)
  self.assertLess(s.index('try{$j.process.Dispose()}finally{'),s.index('Complete-PendingProcessTransfer $j $operationSucceeded'))
  self.assertIn('$script:closing -or -not $Succeeded',self.s);self.assertIn('recording_folder -cne',self.s)
 def test_registration_does_not_silently_rehash_known_or_hide_new(self):
  self.assertIn('$known.ContainsKey($key) -or $seen.ContainsKey($key)',self.s);self.assertIn("$filter.Text='';$tabs.SelectedTab=$programTab",self.s);self.assertNotIn('$script:checks[',self.s)
 def test_existing_registration_batch_only_changes_programs(self):
  start=self.store.read();before=start['config'];r=handle(self.store,'register',dict(paths=[r'C:\Games\New.exe',r'C:\Helpers\New.exe'],generation=0),self.job);c=r['state']['config']
  self.assertEqual(len(c['programs']),2);self.assertEqual([p['path'] for p in c['programs']],[r'C:\Games\New.exe',r'C:\Helpers\New.exe']);self.assertTrue(all(p['sha256']=='a'*64 for p in c['programs']))
  for k in ('mode','blacklist','whitelist','legacy_imports'):self.assertEqual(c[k],before[k])
  self.assertFalse((self.root/'private'/'lab-jobs').exists());self.assertEqual(c['generation'],1)
 def test_inspector_failure_cannot_partially_register_batch(self):
  self.store.read();before=self.store.file.read_bytes();self.bad=r'C:\Missing\B.exe'
  with self.assertRaisesRegex(PolicyError,'fake_missing'):handle(self.store,'register',dict(paths=[r'C:\Apps\A.exe',self.bad],generation=0),self.job)
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_stale_generation_cannot_overwrite_state(self):
  self.store.register([r'C:\Old\Old.exe'],0);before=self.store.file.read_bytes()
  with self.assertRaisesRegex(PolicyError,'config_changed'):handle(self.store,'register',dict(paths=[r'C:\Apps\A.exe'],generation=0),self.job)
  self.assertEqual(self.store.file.read_bytes(),before)
 def test_total_program_limit_is_atomic(self):
  self.store.register([f'C:\\Old\\P{i}.exe' for i in range(31)],0);before=self.store.file.read_bytes()
  with self.assertRaisesRegex(PolicyError,'config_limit'):handle(self.store,'register',dict(paths=[r'C:\Apps\A.exe',r'C:\Apps\B.exe'],generation=1),self.job)
  self.assertEqual(self.store.file.read_bytes(),before)
if __name__=='__main__':unittest.main()
