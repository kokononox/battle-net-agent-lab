import dataclasses,json,os,subprocess,sys,unittest
from pathlib import Path
import test_transfer_controller as fixture_helpers
from transfer_controller import TransferGrant,TransferController
from archive_transfer import ArchiveResponse,archive_url
from release_core import RunCheckpoint,InvalidRelease
from test_release_core import fixture_baseline,target
class ReconcileTests(unittest.TestCase):
 setUp=fixture_helpers.ControllerTests.setUp
 add_stage=fixture_helpers.ControllerTests.add_stage
 close_all=fixture_helpers.ControllerTests.close_all
 approve=fixture_helpers.ControllerTests.approve
 fetch=fixture_helpers.ControllerTests.fetch
 bad=fixture_helpers.ControllerTests.bad
 step=fixture_helpers.ControllerTests.step
 restore=fixture_helpers.ControllerTests.restore
 def pending(self,at='stage_committed'):
  def fault(point):
   if point==at:raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.step(_fault=fault)
 def reconcile(self,**kw):return TransferController.reconcile_pending(self.stages,self.grant,kw.pop('baseline',self.cp.baseline),approved=kw.pop('approved',True),**kw)
 def ledger(self):return json.loads((self.stages[0].path/'transfer.json').read_bytes())
 def test_committed_range_reconciled_without_fetch(self):
  self.pending();before=self.ledger();count=len(self.calls);r=self.reconcile();self.assertTrue(r['reconciled']);self.assertTrue(r['full_object_verified']);self.assertTrue(r['full_object_proof']['full_ckey_verified']);self.assertEqual(r['network_requests'],0);self.assertEqual(len(self.calls),count);after=self.ledger();self.assertEqual(after['reserved_requests'],before['reserved_requests']);self.assertEqual(after['reserved_body_bytes'],before['reserved_body_bytes']);self.assertFalse(after['pending']);self.assertEqual(after['cursor'],1)
 def test_restore_and_continue_remaining_only(self):
  self.pending();self.reconcile();self.controller=self.restore();self.step();self.assertTrue(self.controller.finish()['all_objects_freshly_verified']);self.assertEqual(len(self.calls),2)
 def test_approval_required(self):self.pending();self.bad(self.reconcile,approved=False);self.assertTrue(self.ledger()['pending'])
 def test_no_pending_refused(self):self.bad(self.reconcile)
 def test_uncommitted_reservation_remains_pending(self):
  self.pending('attempt_reserved');before=self.ledger();r=self.reconcile();self.assertFalse(r['reconciled']);self.assertEqual(self.ledger(),before);self.assertFalse(self.calls);self.bad(self.restore)
 def test_corrupt_payload_not_reconciled(self):
  self.pending();s=self.stages[0];(s.path/s.doc['segments'][0]['name']).write_bytes(b'x'*s.spec.encoded_size);self.bad(self.reconcile);self.assertTrue(self.ledger()['pending'])
 def test_modified_segment_digest_cannot_hide_bad_content(self):
  import hashlib
  self.pending();s=self.stages[0];d=json.loads((s.path/'journal.json').read_bytes());p=s.path/d['segments'][0]['name'];raw=p.read_bytes()[:-1]+b'x';p.write_bytes(raw);d['segments'][0]['sha256']=hashlib.sha256(raw).hexdigest();(s.path/'journal.json').write_bytes(s._encode(d));self.bad(self.reconcile)
 def test_changed_previous_journal_refused(self):
  self.pending();p=self.stages[0].path/'transfer.json';d=self.ledger();d['journal_hashes'][0]='f'*64;p.write_text(json.dumps(d));self.bad(self.reconcile)
 def test_changed_other_stage_refused(self):
  self.pending();s=self.stages[1];raw=self.payloads[s.identity];s.append(ArchiveResponse(archive_url(s.cp,s.source),100,100+len(raw)-1,999999999,'"entity"',raw),(0,len(raw)-1));self.bad(self.reconcile)
 def test_changed_baseline_refused(self):self.pending();self.bad(self.reconcile,baseline=fixture_baseline('1.0.1.101'))
 def test_changed_target_refused(self):self.pending();self.stages[0].cp=RunCheckpoint(self.cp.baseline,target('20.0.0.100001'));self.bad(self.reconcile)
 def test_changed_source_refused(self):self.pending();self.stages[0].source=dataclasses.replace(self.stages[0].source,offset=101);self.bad(self.reconcile)
 def test_mutated_grant_refused(self):self.pending();self.grant.max_requests+=1;self.bad(self.reconcile)
 def test_missing_segment_refused(self):self.pending();s=self.stages[0];(s.path/s.doc['segments'][0]['name']).unlink();self.bad(self.reconcile)
 def test_abandoned_lock_preserved(self):
  self.pending();p=self.stages[0].path/'writer.lock';p.write_bytes(b'keep');self.bad(self.reconcile);self.assertEqual(p.read_bytes(),b'keep')
 def test_repeated_reconciliation_refused(self):self.pending();self.reconcile();before=self.ledger();self.bad(self.reconcile);self.assertEqual(self.ledger(),before)
 def test_fault_before_publish_leaves_pending(self):
  self.pending();before=self.ledger()
  def fault(at):raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.reconcile(_fault=fault)
  self.assertEqual(self.ledger(),before);self.assertTrue(self.reconcile()['reconciled'])
 def test_fault_after_publish_can_restore(self):
  self.pending()
  def fault(at):
   if at=='reconcile_committed':raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.reconcile(_fault=fault)
  self.assertFalse(self.ledger()['pending']);self.controller=self.restore();self.step();self.assertTrue(self.controller.finish()['all_objects_freshly_verified'])
 def test_partial_object_not_claimed_full_proof(self):
  self.close_all();self.stages=[];self.add_stage(9,True);self.stages=tuple(self.stages);self.grant=self.approve();self.controller=TransferController.create(self.stages,self.grant,self.fetch);self.pending();r=self.reconcile();self.assertFalse(r['full_object_verified']);self.assertIsNone(r['full_object_proof']);self.controller=self.restore();self.step();self.assertTrue(self.controller.finish()['all_objects_freshly_verified'])
 def test_no_apply_or_installed_proof(self):
  self.pending();r=self.reconcile();self.assertFalse(r['apply_authorized']);self.assertFalse(r['installation_ready']);self.assertFalse(r['active_generation_proven']);self.assertIsNone(r['required_network_download_bytes'])
 def test_fresh_process_local_reconciliation(self):
  self.pending();self.close_all();p=self.root/'reconcile.json';p.write_text(json.dumps({'grant':self.grant.serialize().decode(),'cp':self.cp.serialize().decode(),'paths':[str(s.path)for s in self.stages],'specs':[s.spec.public()for s in self.stages],'sources':[s.source.public()for s in self.stages]}))
  code='''import json,sys,os
from pathlib import Path
from release_core import RunCheckpoint
from stream_blte import StreamObjectSpec
from stream_stage import StreamStage
from windows_stream_stage import WindowsStreamStage
from archive_transfer import ArchiveSource
from transfer_controller import TransferGrant,TransferController
x=json.loads(Path(sys.argv[1]).read_bytes());cp=RunCheckpoint.restore(x['cp'].encode());cls=WindowsStreamStage if os.name=='nt'else StreamStage;stages=tuple(cls.restore(p,cp,StreamObjectSpec(**s),ArchiveSource(**a),cp.baseline)for p,s,a in zip(x['paths'],x['specs'],x['sources']))
try:
 g=TransferGrant.restore(x['grant'].encode(),stages,approved=True);r=TransferController.reconcile_pending(stages,g,cp.baseline,approved=True);assert r['reconciled'] and r['full_object_verified'] and r['network_requests']==0 and r['reserved_requests']==1;print('local_reconciliation_only_no_fetch')
finally:
 for s in stages:s.close()
'''
  result=subprocess.run([sys.executable,'-c',code,str(p)],cwd=Path(__file__).parent,env={k:v for k,v in os.environ.items()if k in('SystemRoot','PATH','TEMP','TMP')},capture_output=True,timeout=30);self.assertEqual(result.returncode,0,'synthetic_reconciliation_child_failed');self.assertEqual(result.stdout.strip(),b'local_reconciliation_only_no_fetch');self.assertFalse(self.ledger()['pending'])
 def setup_large(self):
  self.close_all();self.stages=[];self.add_stage(9,True);self.stages=tuple(self.stages);self.grant=self.approve();self.controller=TransferController.create(self.stages,self.grant,self.fetch)
 shared_stages=fixture_helpers.ControllerTests.shared_stages
 def test_second_segment_reconstructs_nonempty_prior(self):
  self.setup_large();self.step();self.pending();r=self.reconcile();self.assertTrue(r['full_object_verified']);self.controller=self.restore();self.assertTrue(self.controller.finish()['all_objects_freshly_verified']);self.assertEqual(len(self.calls),2)
 def test_more_than_reserved_segment_refused(self):
  self.setup_large();self.pending();s=self.stages[0];a,b=s.next_range();raw=self.payloads[s.identity];s.append(ArchiveResponse(archive_url(s.cp,s.source),s.source.offset+a,s.source.offset+b,999999999,'"entity"',raw[a:b+1]),(a,b));self.bad(self.reconcile)
 def test_shared_archive_consistent_reconciliation(self):
  self.shared_stages();self.step();self.pending();self.assertTrue(self.reconcile()['reconciled']);self.controller=self.restore();self.assertTrue(self.controller.finish()['all_objects_freshly_verified'])
 def test_shared_archive_entity_change_not_adopted(self):
  self.shared_stages();self.step();self.pending();s=self.stages[1];p=s.path/'journal.json';d=json.loads(p.read_bytes());d['etag']='"other"';p.write_bytes(s._encode(d));self.bad(self.reconcile)
 def test_uncommitted_attempt_still_checks_existing_prefix(self):
  self.setup_large();self.step();self.pending('attempt_reserved');s=self.stages[0];p=s.path/s.doc['segments'][0]['name'];p.write_bytes(b'x'*p.stat().st_size);self.bad(self.reconcile)
