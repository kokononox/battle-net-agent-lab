import dataclasses,json,os,subprocess,sys,unittest
from pathlib import Path
import test_transfer_controller as fixtures
import test_transfer_reconcile as recovery
from transfer_controller import TransferGrant,TransferController,encode
from transfer_scope import retire_uncommitted,approve_successor,create_successor
from test_release_core import fixture_baseline
class ScopeTests(unittest.TestCase):
 setUp=fixtures.ControllerTests.setUp
 add_stage=fixtures.ControllerTests.add_stage
 close_all=fixtures.ControllerTests.close_all
 approve=fixtures.ControllerTests.approve
 fetch=fixtures.ControllerTests.fetch
 bad=fixtures.ControllerTests.bad
 step=fixtures.ControllerTests.step
 restore=fixtures.ControllerTests.restore
 pending=recovery.ReconcileTests.pending
 ledger=recovery.ReconcileTests.ledger
 def retire(self,**kw):return retire_uncommitted(self.stages,self.grant,kw.pop('baseline',self.cp.baseline),approved=kw.pop('approved',True),**kw)
 def new_grant(self,**kw):return approve_successor(self.stages,kw.get('baseline',self.cp.baseline),max_requests=kw.get('requests',8),max_body_bytes=4*1024**2,approved=kw.get('approved',True))
 def successor(self,g=None,**kw):return create_successor(self.stages,g or self.new_grant(),self.fetch,kw.pop('baseline',self.cp.baseline),approved=kw.pop('approved',True),**kw)
 def setup_retired(self):self.pending('attempt_reserved');return self.retire()
 def test_retire_keeps_consumed_reservation(self):
  before_calls=len(self.calls);self.pending('attempt_reserved');before=self.ledger();r=self.retire();self.assertFalse(r['budget_refunded']);self.assertEqual(r['retired_reserved_requests'],1);self.assertEqual(r['retired_reserved_application_body_bytes'],before['reserved_body_bytes']);self.assertEqual(r['network_requests'],0);self.assertEqual(len(self.calls),before_calls);self.assertEqual(self.ledger()['format'],'retired-transfer-ledger-1');self.assertTrue((self.stages[0].path/(self.grant.identity+'.json')).is_file())
 def test_retirement_needs_approval(self):self.pending('attempt_reserved');self.bad(self.retire,approved=False);self.assertTrue(self.ledger()['pending'])
 def test_no_pending_not_retired(self):self.bad(self.retire)
 def test_committed_range_must_reconcile_not_retire(self):self.pending();self.bad(self.retire);self.assertTrue(self.ledger()['pending'])
 def test_old_controller_cannot_continue_after_retirement(self):self.setup_retired();self.bad(self.step);self.bad(self.restore)
 def test_successor_approval_required(self):self.setup_retired();self.bad(self.new_grant,approved=False)
 def test_successor_creation_approval_required(self):self.setup_retired();g=self.new_grant();self.bad(self.successor,g,approved=False)
 def test_new_nonce_for_identical_plan(self):self.assertNotEqual(self.approve().identity,self.approve().identity)
 def test_old_grant_cannot_be_reused(self):self.setup_retired();self.bad(self.successor,self.grant)
 def test_ordinary_new_grant_does_not_bind_history(self):self.setup_retired();self.bad(self.successor,self.approve())
 def test_successor_preserves_lifetime_accounting(self):
  self.setup_retired();g=self.new_grant();c=self.successor(g);r=c.summary();self.assertEqual(r['reserved_requests'],0);self.assertEqual(r['lifetime_reserved_requests'],1);self.assertFalse(self.calls);c.step(self.cp.baseline);c.step(self.cp.baseline);r=c.finish();self.assertEqual(r['lifetime_reserved_requests'],3);self.assertEqual(r['retired_scope_count'],1);self.assertTrue(r['all_objects_freshly_verified']);self.bad(self.restore)
 def test_repeated_retirement_idempotent_without_refund(self):
  self.setup_retired();before=self.ledger();r=self.retire();self.assertEqual(r['status'],'already_retired_no_retry');self.assertEqual(r['lifetime_reserved_requests'],1);self.assertEqual(self.ledger(),before)
 def test_successor_repeated_creation_refused(self):self.setup_retired();g=self.new_grant();self.successor(g);self.bad(self.successor,g)
 def test_marker_digest_tamper_refused(self):
  self.setup_retired();p=self.stages[0].path/'transfer.json';d=self.ledger();d['receipt_sha256']='f'*64;p.write_text(json.dumps(d));self.bad(self.new_grant)
 def test_retirement_receipt_corruption_refused(self):
  self.setup_retired();p=self.stages[0].path/(self.grant.identity+'.json');p.write_bytes(p.read_bytes()+b'x');self.bad(self.new_grant)
 def test_missing_history_receipt_blocks_restore(self):
  self.setup_retired();g=self.new_grant();c=self.successor(g);(self.stages[0].path/(self.grant.identity+'.json')).unlink();self.bad(TransferController.restore,self.stages,g,self.fetch);self.bad(c.step,self.cp.baseline)
 def test_hardlinked_receipt_refused(self):
  self.setup_retired();p=self.stages[0].path/(self.grant.identity+'.json');(self.root/'alias.json').hardlink_to(p);self.bad(self.new_grant)
 def test_history_cannot_be_silently_dropped(self):
  self.setup_retired();g=self.new_grant();self.successor(g);p=self.stages[0].path/'transfer.json';d=self.ledger();d['prior_scopes']=[];p.write_text(json.dumps(d));self.bad(TransferController.restore,self.stages,g,self.fetch)
 def test_history_budget_tamper_refused(self):
  self.setup_retired();g=self.new_grant();self.successor(g);p=self.stages[0].path/'transfer.json';d=self.ledger();d['prior_scopes'][0]['reserved_requests']=2;p.write_text(json.dumps(d));self.bad(TransferController.restore,self.stages,g,self.fetch)
 def test_fault_after_receipt_can_finish_retirement_explicitly(self):
  self.pending('attempt_reserved')
  def fault(at):raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.retire(_fault=fault)
  self.assertTrue(self.ledger()['pending']);self.bad(self.restore);self.assertEqual(self.retire()['retired_reserved_requests'],1)
 def test_fault_after_retirement_marker_is_idempotent(self):
  self.pending('attempt_reserved')
  def fault(at):
   if at=='retirement_committed':raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.retire(_fault=fault)
  self.assertEqual(self.retire()['status'],'already_retired_no_retry')
 def test_fault_before_successor_publish_preserves_marker(self):
  self.setup_retired();g=self.new_grant();before=self.ledger()
  def fault(at):raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.successor(g,_fault=fault)
  self.assertEqual(self.ledger(),before);self.assertEqual(self.successor(g).summary()['lifetime_reserved_requests'],1)
 def test_fault_after_successor_publish_can_restore(self):
  self.setup_retired();g=self.new_grant()
  def fault(at):
   if at=='successor_committed':raise RuntimeError('synthetic interruption')
  with self.assertRaises(RuntimeError):self.successor(g,_fault=fault)
  c=TransferController.restore(self.stages,g,self.fetch);self.assertEqual(c.summary()['lifetime_reserved_requests'],1);self.assertFalse(self.calls)
 def test_changed_baseline_cannot_retire(self):self.pending('attempt_reserved');self.bad(self.retire,baseline=fixture_baseline('1.0.1.101'))
 def test_changed_baseline_cannot_approve_successor(self):self.setup_retired();self.bad(self.new_grant,baseline=fixture_baseline('1.0.1.101'))
 def test_abandoned_lock_not_removed(self):
  self.pending('attempt_reserved');p=self.stages[0].path/'writer.lock';p.write_bytes(b'keep');self.bad(self.retire);self.assertEqual(p.read_bytes(),b'keep')
 def test_two_retired_scopes_form_checked_chain(self):
  self.setup_retired();first=self.grant;self.grant=self.new_grant();self.controller=self.successor(self.grant);self.pending('attempt_reserved');self.retire();g=self.new_grant();c=self.successor(g);self.assertEqual(c.summary()['retired_scope_count'],2);self.assertEqual(c.summary()['lifetime_reserved_requests'],2);self.assertTrue((self.stages[0].path/(first.identity+'.json')).exists())
 def test_legacy_empty_history_grant_and_ledger_readable(self):
  d=json.loads(self.grant.serialize());d['format']='owned-transfer-grant-1';del d['scope_nonce'];del d['prior_scopes_sha256'];g=TransferGrant.restore(encode(d),self.stages,approved=True);p=self.stages[0].path/'transfer.json';ld=self.ledger();ld['format']='owned-transfer-ledger-1';ld['grant_sha256']=g.identity;del ld['prior_scopes'];p.write_bytes(encode(ld));c=TransferController.restore(self.stages,g,self.fetch);c.step(self.cp.baseline);self.assertEqual(c.summary()['retired_scope_count'],0)
 def test_new_scope_budget_too_small_refused(self):self.setup_retired();self.bad(self.new_grant,requests=1)
 def test_no_installation_authority_granted(self):
  r=self.setup_retired();self.assertFalse(r['installation_ready']);self.assertFalse(r['apply_authorized']);self.assertFalse(r['automatic_retry']);c=self.successor();self.assertFalse(c.summary()['apply_authorized'])
 def test_corrupt_prior_completed_prefix_prevents_retirement(self):
  self.step();self.pending('attempt_reserved');s=self.stages[0];(s.path/s.doc['segments'][0]['name']).write_bytes(b'x'*s.spec.encoded_size);self.bad(self.retire)
 def test_history_limit_rejected_before_file_reads(self):
  from transfer_scope import validate_history_rows,MAX_PRIOR_SCOPES
  rows=[{'receipt_name':format(i,'064x')+'.json','receipt_sha256':'a'*64,'grant_sha256':format(i,'064x'),'reserved_requests':1,'reserved_body_bytes':1}for i in range(MAX_PRIOR_SCOPES+1)];self.bad(validate_history_rows,rows)
 def test_fresh_process_retirement_and_successor_restore(self):
  self.pending('attempt_reserved');self.close_all();p=self.root/'scope.json';p.write_text(json.dumps({'grant':self.grant.serialize().decode(),'cp':self.cp.serialize().decode(),'paths':[str(s.path)for s in self.stages],'specs':[s.spec.public()for s in self.stages],'sources':[s.source.public()for s in self.stages]}))
  code='''import json,sys,os
from pathlib import Path
from release_core import RunCheckpoint
from stream_blte import StreamObjectSpec
from stream_stage import StreamStage
from windows_stream_stage import WindowsStreamStage
from archive_transfer import ArchiveSource
from transfer_controller import TransferGrant,TransferController
from transfer_scope import retire_uncommitted,approve_successor,create_successor
x=json.loads(Path(sys.argv[1]).read_bytes());cp=RunCheckpoint.restore(x['cp'].encode());cls=WindowsStreamStage if os.name=='nt'else StreamStage;stages=tuple(cls.restore(p,cp,StreamObjectSpec(**s),ArchiveSource(**a),cp.baseline)for p,s,a in zip(x['paths'],x['specs'],x['sources']))
def forbidden(req):raise RuntimeError('network_forbidden')
try:
 if len(sys.argv)==2:
  g=TransferGrant.restore(x['grant'].encode(),stages,approved=True);r=retire_uncommitted(stages,g,cp.baseline,approved=True);assert r['network_requests']==0 and r['retired_reserved_requests']==1
  g=approve_successor(stages,cp.baseline,max_requests=8,max_body_bytes=4*1024**2,approved=True);c=create_successor(stages,g,forbidden,cp.baseline,approved=True);x['successor']=g.serialize().decode();Path(sys.argv[1]).write_text(json.dumps(x))
 else:
  g=TransferGrant.restore(x['successor'].encode(),stages,approved=True);c=TransferController.restore(stages,g,forbidden)
 assert c.summary()['lifetime_reserved_requests']==1 and c.summary()['reserved_requests']==0;print('scope_history_preserved_no_fetch')
finally:
 for s in stages:s.close()
'''
  for args in ([],['restore']):
   result=subprocess.run([sys.executable,'-c',code,str(p)]+args,cwd=Path(__file__).parent,env={k:v for k,v in os.environ.items()if k in('SystemRoot','PATH','TEMP','TMP')},capture_output=True,timeout=30);self.assertEqual(result.returncode,0,'synthetic_scope_child_failed');self.assertEqual(result.stdout.strip(),b'scope_history_preserved_no_fetch')
