"""Direct live-file variant: mandatory gates plus process-stop recovery."""
import fcntl,hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import agent_archive_insert as insert
import agent_archive_direct as direct
import patch_audit as a
import retail_direct_cycle as c
import source_binding as b
ORACLES=[Path(os.environ[n]).resolve() for n in ('BIND_ORACLE','LOOKUP_ORACLE','SPAN_ORACLE','DIRECT_ORACLE')]
TEMPLATE=Path(os.environ['RETAIL_DIRECT_CYCLE_TEMPLATE']).resolve()
RECOVERY=[]
def snapshot(root):return {f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in root.iterdir()}
class DirectCycleTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'cycle';shutil.copytree(TEMPLATE,self.root)
 def tearDown(self):self.temp.cleanup()
 def status(self):return c.status(self.root,*ORACLES)
 def advance(self):return c.advance(self.root,*ORACLES)
 def child(self,phase):
  args=[sys.executable,'-B',str(Path(c.__file__).resolve()),'advance','--root',str(self.root),'--test-exit-after',phase]
  for name,value in zip(('bind','lookup','span','direct'),ORACLES):args+=['--'+name+'-oracle',str(value)]
  return subprocess.run(args,capture_output=True,timeout=30)
 def recovery(self,phase):
  before=snapshot(self.root);source=(self.root/'data.000').read_bytes()[:668]
  child=self.child(phase);self.assertEqual(child.returncode,91,child.stderr.decode());self.assertEqual(child.stdout,b'');self.assertEqual(child.stderr,b'')
  stopped=self.status();published=phase in ('control_published','committed')
  self.assertEqual(stopped['target_published'],published)
  self.assertEqual(stopped['native_read_addresses'],[480,668,480,668] if published else [480]*4)
  resumed=self.advance();self.assertTrue(resumed['target_published']);self.assertEqual(resumed['custom_resume_state'],'committed');self.assertEqual(resumed['native_read_addresses'],[480,668,480,668]);self.assertEqual((resumed['open_calls'],resumed['constructor_calls']),(1,1));self.assertTrue(resumed['mandatory_original_insert_cache_span_gate'])
  self.assertEqual((self.root/'data.000').read_bytes()[:668],source)
  for name,digest in before.items():
   if name not in ('data.000','shmem'):self.assertEqual(snapshot(self.root)[name],digest)
  done=snapshot(self.root);again=self.advance();self.assertTrue(again['idempotent_noop']);self.assertEqual(snapshot(self.root),done)
  self.assertNotIn(insert.MARKER,done)
  RECOVERY.append({'phase':phase,'child_exit':child.returncode,'published_at_stop':stopped['target_published'],'data_bytes_at_stop':stopped['data_bytes'],'visible_native_read_addresses_at_stop':stopped['native_read_addresses'],'resumed_committed':True,'resumed_native_read_addresses':resumed['native_read_addresses'],'resumed_open_calls':resumed['open_calls'],'resumed_constructor_calls':resumed['constructor_calls'],'original_prefix_source_and_initial_indexes_unchanged':True,'idempotent_noop_after_resume':True,'extra_marker_in_cycle':False,'native_io_on_locked_live_archive':resumed['native_io_on_locked_live_archive'],'snapshots_created':resumed['direct_live_read']['snapshots_created']})
 def test_initial_gate_uses_source_range_four_times(self):
  r=self.status();self.assertEqual(r['native_read_addresses'],[480]*4);self.assertEqual(r['visible_objects'],1);self.assertTrue(r['lookup_returned_addresses_consumed_by_native_io'])
 def test_normal_advance_then_status(self):
  r=self.advance();self.assertTrue(r['target_published']);self.assertEqual(r['native_read_addresses'],[480,668]*2);self.assertEqual(self.status()['native_read_addresses'],r['native_read_addresses'])
 def test_status_is_readonly_and_no_marker_added(self):
  before=snapshot(self.root);self.status();self.assertEqual(snapshot(self.root),before);self.assertNotIn(insert.MARKER,before)
 def test_candidate_and_published_gates_are_both_called(self):
  original=c.gate;events=[]
  def gate(root,view,*args,**kw):
   candidate=kw.get('candidate',args[3] if len(args)>3 else False);r=original(root,view,*args,**kw);events.append((view['updated'],candidate,list(r['native_read_addresses'])));return r
  with patch.object(c,'gate',gate):self.advance()
  self.assertEqual(events,[(False,False,[480]*4),(False,True,[480,668]*2),(True,False,[480,668]*2)])
 def test_gate_failure_before_transaction_is_nonmutating(self):
  before=snapshot(self.root)
  with patch.object(c,'gate',side_effect=a.AuditError('injected_gate_reject')):
   with self.assertRaises(a.AuditError):self.advance()
  self.assertEqual(snapshot(self.root),before)
 def test_candidate_failure_prevents_control_publish_and_can_resume(self):
  original=c.gate
  def gate(root,view,*args,**kw):
   candidate=kw.get('candidate',args[3] if len(args)>3 else False)
   if candidate:raise a.AuditError('injected_candidate_reject')
   return original(root,view,*args,**kw)
  with patch.object(c,'gate',gate):
   with self.assertRaises(a.AuditError):self.advance()
  self.assertFalse(self.status()['target_published']);self.assertTrue(self.advance()['target_published'])
 def test_postpublication_failure_leaves_prepared_journal_and_can_resume(self):
  original=c.gate
  def gate(root,view,*args,**kw):
   if view['updated']:raise a.AuditError('injected_postpublish_reject')
   return original(root,view,*args,**kw)
  with patch.object(c,'gate',gate):
   with self.assertRaises(a.AuditError):self.advance()
  stopped=self.status();self.assertTrue(stopped['target_published']);self.assertEqual(stopped['custom_resume_state'],'prepared');self.assertEqual(self.advance()['custom_resume_state'],'committed')
 def test_native_read_rejection_is_mandatory(self):
  before=snapshot(self.root)
  with patch.object(direct,'compare',side_effect=a.AuditError('injected_native_read_reject')):
   with self.assertRaises(a.AuditError):self.advance()
  self.assertEqual(snapshot(self.root),before)
 def test_native_short_read_status_zero_is_not_accepted(self):
  original=direct.compare
  def short(*args,**kw):
   rows=original(*args,**kw);r,data=rows[0];r=dict(r,status=0,actual_bytes=187);return [(r,data[:-1])]+rows[1:]
  with patch.object(direct,'compare',short):
   with self.assertRaises(a.AuditError):self.advance()
 def test_native_header_parser_rejection_is_mandatory(self):
  with patch.object(c.span,'compare',side_effect=a.AuditError('injected_header_reject')):
   with self.assertRaises(a.AuditError):self.advance()
 def test_bad_oracle_digest_rejected(self):
  bad=Path(self.temp.name).resolve()/'bad-oracle';bad.mkdir();shutil.copy(ORACLES[3],bad/'archive_direct_oracle');shutil.copy(ORACLES[3].parent/'BUILD-RECEIPT.json',bad/'BUILD-RECEIPT.json');f=bad/'archive_direct_oracle';f.write_bytes(f.read_bytes()+b'!')
  before=snapshot(self.root)
  with self.assertRaises(a.AuditError):c.advance(self.root,*ORACLES[:3],f)
  self.assertEqual(snapshot(self.root),before)
 def test_cooperating_writer_lock_rejected(self):
  with (self.root/'LOCK').open('r+b') as lock:
   fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(a.AuditError):self.advance()
 def test_corrupt_source_rejected_without_control_publish(self):
  f=self.root/'data.000';raw=bytearray(f.read_bytes());raw[530]^=1;f.write_bytes(raw)
  before=snapshot(self.root)
  with self.assertRaises((a.AuditError,b.BindingError)):self.advance()
  self.assertEqual(snapshot(self.root),before)
 def test_corrupt_named_candidate_index_rejected(self):
  self.assertEqual(self.child('index_named').returncode,91);view=c.base.inspect(self.root);f=self.root/view['new_name'];raw=bytearray(f.read_bytes());raw[-1]^=1;f.write_bytes(raw);before=snapshot(self.root)
  with self.assertRaises((a.AuditError,b.BindingError)):self.advance()
  self.assertEqual(snapshot(self.root),before)
 def test_extra_marker_in_strict_cycle_rejected(self):
  (self.root/insert.MARKER).write_text('{}')
  with self.assertRaises(a.AuditError):self.status()
 @classmethod
 def tearDownClass(cls):
  if os.environ.get('DIRECT_CYCLE_RECOVERY_REPORT'):Path(os.environ['DIRECT_CYCLE_RECOVERY_REPORT']).write_text(json.dumps(sorted(RECOVERY,key=lambda x:c.base.PHASES.index(x['phase'])),indent=2)+'\n')
for phase in c.base.PHASES:
 def test(self,phase=phase):self.recovery(phase)
 setattr(DirectCycleTests,'test_recovery_'+phase,test)
if __name__=='__main__':unittest.main(verbosity=2)
