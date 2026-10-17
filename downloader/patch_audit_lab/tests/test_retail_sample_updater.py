"""CLI/workspace/export tests for the OFFLINE ONE-PAIR research application."""
import fcntl,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import agent_archive_direct as direct
import encoding_target as encoding
import patch_audit as a
import retail_sample_updater as app
import source_binding as b
TEMPLATE=Path(os.environ['SAMPLE_UPDATER_TEMPLATE']).resolve()
RECOVERY=[]
def contents(root):return {str(p.relative_to(root)):a.sha256(p.read_bytes()) for p in root.rglob('*') if p.is_file()}
class SampleUpdaterTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.watch=b.Watch()
  for p in TEMPLATE.rglob('*'):
   if p.is_file():cls.watch.file(p)
  cls.portable=Path(json.loads((TEMPLATE/'origin.json').read_text())['portable_root'])
  for p in cls.portable.rglob('*'):
   if p.is_file():cls.watch.file(p)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'workspace';shutil.copytree(TEMPLATE,self.root);self.output=Path(self.temp.name).resolve()/'export.decoded'
 def tearDown(self):self.temp.cleanup()
 def cli(self,mode,*args):return subprocess.run([sys.executable,'-B',str(Path(app.__file__).resolve()),mode,'--workspace',str(self.root),*map(str,args)],capture_output=True,text=True,timeout=30)
 def test_initial_plan_and_visibility(self):
  self.assertFalse(app.status(self.root)['target_published']);p=app.plan(self.root);self.assertEqual(p['action'],'apply_verified_saved_patch');self.assertFalse(p['full_game_build_plan']);self.assertEqual(p['network_requests'],0)
 def test_update_and_export_exact_decoded_target(self):
  r=app.update(self.root);self.assertTrue(r['target_published']);self.assertTrue(r['native_io_on_locked_live_archive']);e=app.export(self.root,self.output);self.assertEqual(e['bytes'],33940);self.assertEqual(a.sha256(self.output.read_bytes()),encoding.TARGET_SHA256)
 def test_repeat_update_is_nonmutating_noop(self):
  app.update(self.root);before=contents(self.root);r=app.update(self.root);self.assertTrue(r['idempotent_noop']);self.assertEqual(contents(self.root),before);self.assertEqual(app.plan(self.root)['action'],'already_published')
 def test_export_before_commit_rejected(self):
  with self.assertRaises(a.AuditError):app.export(self.root,self.output)
  self.assertFalse(self.output.exists())
 def test_existing_export_is_not_overwritten(self):
  app.update(self.root);self.output.write_bytes(b'KEEP')
  with self.assertRaises(a.AuditError):app.export(self.root,self.output)
  self.assertEqual(self.output.read_bytes(),b'KEEP')
 def test_export_inside_workspace_rejected(self):
  app.update(self.root)
  with self.assertRaises(a.AuditError):app.export(self.root,self.root/'do-not-create')
  self.assertFalse((self.root/'do-not-create').exists())
 def test_export_inside_portable_rejected(self):
  app.update(self.root);out=self.portable/'do-not-create-export'
  with self.assertRaises(a.AuditError):app.export(self.root,out)
  self.assertFalse(out.exists())
 def test_origin_configuration_change_rejected(self):
  p=self.root/'origin.json';p.write_bytes(p.read_bytes()+b' ')
  with self.assertRaises(a.AuditError):app.update(self.root)
 def test_tools_configuration_change_rejected(self):
  p=self.root/'tools.json';p.write_bytes(p.read_bytes()+b' ')
  with self.assertRaises(a.AuditError):app.status(self.root)
 def test_competing_app_writer_lock_rejected(self):
  with (self.root/'LOCK').open('r+b') as f:
   fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(a.AuditError):app.update(self.root)
 def test_init_refuses_existing_workspace(self):
  before=contents(self.root)
  with self.assertRaises(a.AuditError):app.init(self.portable,self.root,[])
  self.assertEqual(contents(self.root),before)
 def test_init_output_inside_portable_rejected(self):
  out=self.portable/'do-not-create-workspace'
  with self.assertRaises(a.AuditError):app.init(self.portable,out,[])
  self.assertFalse(out.exists())
 def test_export_symlink_rejected(self):
  app.update(self.root);saved=Path(self.temp.name)/'saved';saved.write_bytes(b'KEEP');self.output.symlink_to(saved)
  with self.assertRaises(a.AuditError):app.export(self.root,self.output)
  self.assertEqual(saved.read_bytes(),b'KEEP')
 def test_cli_plan_update_status_export_workflow(self):
  for mode,args in [('plan',[]),('update',[]),('status',[]),('export',['--out-new',self.output])]:
   p=self.cli(mode,*args);self.assertEqual(p.returncode,0,p.stdout+p.stderr);result=json.loads(p.stdout);self.assertFalse(result['installation_ready'])
  self.assertEqual(a.sha256(self.output.read_bytes()),encoding.TARGET_SHA256)
 def test_corrupt_archive_stops_without_publication(self):
  f=self.root/'cycle'/'data.000';raw=bytearray(f.read_bytes());raw[530]^=1;f.write_bytes(raw);before=contents(self.root)
  with self.assertRaises((a.AuditError,b.BindingError)):app.update(self.root)
  self.assertEqual(contents(self.root),before)
 def test_native_read_failure_prevents_new_transaction(self):
  before=contents(self.root)
  with patch.object(direct,'compare',side_effect=a.AuditError('injected_read_failure')):
   with self.assertRaises(a.AuditError):app.update(self.root)
  self.assertEqual(contents(self.root),before)
 def test_changed_published_target_is_not_exported(self):
  app.update(self.root);p=self.root/'cycle'/'data.000';raw=bytearray(p.read_bytes());raw[-1]^=1;p.write_bytes(raw)
  with self.assertRaises((a.AuditError,b.BindingError)):app.export(self.root,self.output)
  self.assertFalse(self.output.exists())
 def test_atomic_export_race_never_overwrites_existing_file(self):
  app.update(self.root);original=app.legacy.publish_index_noreplace
  def race(src,dst):Path(dst).write_bytes(b'RACE-WINNER');return original(src,dst)
  with patch.object(app.legacy,'publish_index_noreplace',race):
   with self.assertRaises(a.AuditError):app.export(self.root,self.output)
  self.assertEqual(self.output.read_bytes(),b'RACE-WINNER');self.assertFalse(list(self.output.parent.glob('.retail-sample-export-*.tmp')))
 def recovery(self,phase):
  stopped=self.cli('update','--test-exit-after',phase);self.assertEqual(stopped.returncode,91,stopped.stdout+stopped.stderr)
  state=app.status(self.root);self.assertEqual(state['target_published'],phase in ('control_published','committed'))
  resumed=self.cli('update');self.assertEqual(resumed.returncode,0,resumed.stdout+resumed.stderr);final=json.loads(resumed.stdout);self.assertEqual(final['resume_state'],'committed')
  exported=app.export(self.root,self.output);self.assertEqual(exported['sha256'],encoding.TARGET_SHA256);before=contents(self.root);self.assertTrue(app.update(self.root)['idempotent_noop']);self.assertEqual(contents(self.root),before)
  RECOVERY.append({'phase':phase,'cli_exit_at_stop':91,'published_at_stop':state['target_published'],'cli_resume_committed':True,'exported_bytes':exported['bytes'],'exported_sha256':exported['sha256'],'repeat_update_nonmutating_noop':True,'installation_ready':False})
 @classmethod
 def tearDownClass(cls):
  cls.watch.check()
  if os.environ.get('SAMPLE_UPDATER_RECOVERY_REPORT'):Path(os.environ['SAMPLE_UPDATER_RECOVERY_REPORT']).write_text(json.dumps(sorted(RECOVERY,key=lambda x:app.engine.base.PHASES.index(x['phase'])),indent=2)+'\n')
for phase in app.engine.base.PHASES:
 def test(self,phase=phase):self.recovery(phase)
 setattr(SampleUpdaterTests,'test_cli_recovery_'+phase,test)
if __name__=='__main__':unittest.main(verbosity=2)
