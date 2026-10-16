import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cache_evidence as cache
import downloader_controller as ui
import local_casc as local
import local_review as review
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse
import test_local_casc as lt


class OfflineReviewTests(unittest.TestCase):
    make_plan=lt.LocalTests.make_plan
    source_hashes=lt.LocalTests.source_hashes
    def setUp(self):
        lt.LocalTests.setUp(self)
        # Same content fixture, GUI-owned filename and supported transfer routes.
        new=self.plan.with_name('content-plan-'+os.urandom(16).hex()+'.sqlite');os.replace(self.plan,new);self.plan=new
        c=sqlite3.connect(self.plan)
        try:c.execute("UPDATE plan SET route_kind='archive_range'");c.commit()
        finally:c.close()
        _,self.inv=local.inventory(self.lab,self.plan,self.folder)
        self.first,self.seed=local.verify_batch(self.lab,self.plan,self.inv,max_candidates=1)
        with store.input_db(self.lab,self.inv) as (db,_):last_key=db.execute('SELECT ekey FROM candidates ORDER BY id DESC LIMIT 1').fetchone()[0]
        last=self.keys.index(last_key)
        self.decoded=self.base/'old-staging'/'third.bin';self.decoded.parent.mkdir();self.decoded.write_bytes(self.data[last])
        _,self.ri=reuse.inventory(self.lab,self.plan,explicit=[cache.Candidate(self.keys[last],self.decoded,'decoded')],local_inputs=[(self.inv,self.seed)])
        _,self.re=reuse.verify_batch(self.lab,self.plan,self.ri)
        _,self.queue=reuse.make_queue(self.lab,self.plan,self.ri,self.re)
        ui.save_state(self.lab,self.plan,self.queue)
        self.network=patch.object(core.HTTPS,'open',side_effect=AssertionError('offline operation attempted network'));self.network.start();self.addCleanup(self.network.stop)
    def pointer(self):return json.loads(ui._state_path(self.lab).read_text())
    def change(self,fn):
        s=self.pointer();fn(s);core.atomic_json(ui._state_path(self.lab),s)
    def current(self):return review.status(self.lab)['local_verification_summary']
    def test_old_gui_migrates_through_exact_queue_references_no_scan(self):
        r=review.status(self.lab);self.assertEqual(r['local_verification_summary']['candidate_rows_completed'],1)
        self.assertEqual(self.pointer()['local_review']['latest_local']['name'],self.seed.name);self.assertEqual(r['network_requests'],0)
    def test_continue_starts_after_old_cursor_not_from_zero(self):
        seen=[];original=local.cache._verify
        def prove(*a,**kw):seen.append(a[2]);return original(*a,**kw)
        before=self.source_hashes()
        with patch.object(local.cache,'_verify',side_effect=prove):r=review.continue_review(self.lab,max_batches=1,max_candidates=1)
        self.assertEqual(r['local_verification_summary']['candidate_rows_completed'],2);self.assertEqual(len(seen),1)
        self.assertEqual(self.source_hashes(),before);self.assertTrue(r['queue_needs_refresh']);self.assertTrue(review.queue_needs_refresh(self.lab))
    def test_complete_and_merge_preserves_old_decoded_proof_and_unions_keys(self):
        r=review.continue_review(self.lab,max_batches=4,max_candidates=1)
        self.assertEqual(r['local_verification_summary']['candidate_rows_pending'],0)
        report,p,q=review.refresh_queue(self.lab)
        self.assertEqual(report['queue_summary']['verified_encoded_objects_reusable'],3)
        self.assertEqual(report['queue_summary']['remaining_conditional_transfer_candidates'],0)
        self.assertFalse(review.queue_needs_refresh(self.lab));self.assertEqual(ui.load_state(self.lab),(p,q))
        self.assertIsNone(report['required_network_download_bytes']);self.assertFalse(report['installation_ready'])
        self.assertEqual(reuse.checked_queue(self.lab,p,q)['target_objects'],3)
        with store.input_db(self.lab,q) as (db,_):self.assertEqual(db.execute('SELECT COUNT(*) FROM queue').fetchone()[0],3)
    def test_partial_merge_keeps_decoded_only_not_encoded(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1)
        r,_,_=review.refresh_queue(self.lab)
        self.assertEqual(r['queue_summary']['verified_encoded_objects_reusable'],2)
        self.assertEqual(r['queue_summary']['availability_counts']['decoded_content_only'],1)
    def test_existing_published_queue_stays_valid_after_next_batch(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1);_,p,q=review.refresh_queue(self.lab)
        review.continue_review(self.lab,max_batches=1,max_candidates=1)
        self.assertEqual(reuse.checked_queue(self.lab,p,q)['verified_encoded_objects_reusable'],2)
    def test_sources_change_blocks_resume(self):
        review.status(self.lab);p=self.folder/'data.000';p.write_bytes(p.read_bytes()+b'changed')
        with self.assertRaises(core.RepairError):review.continue_review(self.lab)
    def test_source_file_set_change_blocks_resume(self):
        review.status(self.lab);(self.folder/'shmem').write_bytes(b'new')
        with self.assertRaises(core.RepairError):review.continue_review(self.lab)
    def test_decoded_source_change_blocks_queue_refresh(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1);self.decoded.write_bytes(b'changed')
        with self.assertRaises(core.RepairError):review.refresh_queue(self.lab)
    def test_reference_traversal_refused(self):
        review.status(self.lab);self.change(lambda s:s['local_review']['latest_local'].update(name='../../other.sqlite'))
        with self.assertRaisesRegex(core.RepairError,'owned_filename'):review.status(self.lab)
    def test_mutated_checkpoint_fingerprint_refused(self):
        review.status(self.lab)
        self.change(lambda s:s['local_review']['latest_local'].update(fingerprint=[0,0,0,0]))
        with self.assertRaisesRegex(core.RepairError,'referenced_file_changed'):review.status(self.lab)
    def test_ambiguous_anchor_refused_not_newest(self):
        c=sqlite3.connect(self.queue)
        try:
            snap=json.loads(c.execute("SELECT value FROM metadata WHERE name='source_snapshot'").fetchone()[0]);snap['local_snapshots'].append(snap['local_snapshots'][0]);c.execute("UPDATE metadata SET value=? WHERE name='source_snapshot'",(json.dumps(snap),));c.commit()
        finally:c.close()
        with self.assertRaisesRegex(core.RepairError,'one_existing_local_snapshot'):review.status(self.lab)
    def test_no_local_anchor_refused(self):
        _,i=reuse.inventory(self.lab,self.plan);_,e=reuse.verify_batch(self.lab,self.plan,i);_,q=reuse.make_queue(self.lab,self.plan,i,e);ui.save_state(self.lab,self.plan,q)
        with self.assertRaisesRegex(core.RepairError,'one_existing_local_snapshot'):review.status(self.lab)
    def test_cancel_between_batches_retains_completed_checkpoint(self):
        event=threading.Event()
        def notice(e):
            if e['stage']=='local_checkpoint_saved':event.set()
        r=review.continue_review(self.lab,max_batches=3,max_candidates=1,cancel=event,notify=notice)
        self.assertEqual(r['completed_batches_this_run'],1);self.assertIn('cancelled',r['status']);self.assertEqual(self.current()['candidate_rows_completed'],2)
    def test_pre_cancel_no_pointer_changes(self):
        before=ui._state_path(self.lab).read_bytes();event=threading.Event();event.set()
        with self.assertRaises(core.Cancelled):review.continue_review(self.lab,cancel=event)
        self.assertEqual(ui._state_path(self.lab).read_bytes(),before)
    def test_no_progress_budget_pauses_without_loop(self):
        r=review.continue_review(self.lab,byte_budget=1,max_batches=32)
        self.assertEqual(r['completed_batches_this_run'],1);self.assertEqual(r['status'],'next_candidate_exceeds_local_read_budget');self.assertEqual(self.current()['candidate_rows_completed'],1)
    def test_invalid_limits_before_any_checkpoint(self):
        for args in ({'max_batches':0},{'max_batches':True},{'max_batches':513},{'byte_budget':0},{'max_candidates':4097}):
            with self.assertRaises(core.RepairError):review.continue_review(self.lab,**args)
    def test_public_reports_contain_no_private_paths(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1)
        for p in (self.lab.root/'objects').glob('Retail-Local-Review-to-share-*.json'):
            self.assertNotIn(str(self.base),p.read_text());self.assertNotIn('https://',p.read_text())
    def test_already_complete_does_not_publish_another_local_checkpoint(self):
        review.continue_review(self.lab,max_batches=4,max_candidates=1);before=self.pointer()['local_review']['latest_local']
        r=review.continue_review(self.lab)
        self.assertEqual(r['completed_batches_this_run'],0);self.assertEqual(self.pointer()['local_review']['latest_local'],before)
    def test_failed_merge_retains_old_ui_queue_and_local_progress(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1)
        before=ui._state_path(self.lab).read_bytes()
        with patch.object(reuse,'make_queue',side_effect=core.RepairError('injected_queue_failure')):
            with self.assertRaises(core.RepairError):review.refresh_queue(self.lab)
        self.assertEqual(ui._state_path(self.lab).read_bytes(),before);self.assertEqual(self.current()['candidate_rows_completed'],2)
    def test_concurrent_pointer_change_not_overwritten(self):
        review.status(self.lab);before=review._publish
        def race(lab,data,fp,p,q):
            s=self.pointer();s['concurrent_change']=True;core.atomic_json(ui._state_path(lab),s)
            return before(lab,data,fp,p,q)
        with patch.object(review,'_publish',side_effect=race):
            with self.assertRaisesRegex(core.RepairError,'session_changed'):review.continue_review(self.lab,max_batches=1,max_candidates=1)
        self.assertTrue(self.pointer()['concurrent_change'])
    def test_intermediate_checkpoints_pruned_but_seed_retained(self):
        for _ in range(5):review.continue_review(self.lab,max_batches=1,byte_budget=1)
        paths=list((self.lab.root/'objects').glob('local-casc-evidence-*.sqlite'))
        self.assertEqual(len(paths),3);self.assertTrue(self.seed.exists())
        record=self.pointer()['local_review']
        self.assertTrue((self.lab.root/'objects'/record['latest_local']['name']).exists())
        self.assertTrue((self.lab.root/'objects'/record['previous_generated']['name']).exists())
    def test_published_checkpoint_never_pruned_by_subsequent_batches(self):
        review.continue_review(self.lab,max_batches=1,byte_budget=1)
        _,p,q=review.refresh_queue(self.lab)
        pinned=self.pointer()['local_review']['latest_local']['name']
        for _ in range(4):review.continue_review(self.lab,max_batches=1,byte_budget=1)
        self.assertTrue((self.lab.root/'objects'/pinned).exists());reuse.checked_queue(self.lab,p,q)
    def test_seed_claim_sha256_and_evidence_are_preserved_in_merge(self):
        review.continue_review(self.lab,max_batches=1,max_candidates=1);_,p,q=review.refresh_queue(self.lab)
        with store.input_db(self.lab,q) as (db,_):inputs=reuse._meta(db,'private_evidence_inputs')
        inventory=next(Path(n) for n in inputs if Path(n).name.startswith('reuse-inventory-'))
        with store.input_db(self.lab,inventory) as (db,_):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM candidates WHERE source_path=?',(str(self.decoded),)).fetchone()[0],1)
    def test_cannot_start_in_game_root(self):
        (self.lab.root.parent/'.build.info').write_text('marker')
        with self.assertRaisesRegex(core.RepairError,'workspace_inside_game_root'):review.status(self.lab)
    def test_queue_not_rebuilt_automatically_for_every_local_batch(self):
        before=self.queue.read_bytes()
        review.continue_review(self.lab,max_batches=2,max_candidates=1)
        self.assertEqual(ui.load_state(self.lab)[1],self.queue);self.assertEqual(before,self.queue.read_bytes())
    def test_low_disk_retains_durable_previous_checkpoint(self):
        review.status(self.lab);before=ui._state_path(self.lab).read_bytes()
        with patch.object(local.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
            with self.assertRaisesRegex(core.RepairError,'insufficient_lab_space'):review.continue_review(self.lab,max_batches=1)
        self.assertEqual(ui._state_path(self.lab).read_bytes(),before)
    def test_prune_skips_stale_session_view(self):
        review.continue_review(self.lab,max_batches=1,byte_budget=1)
        old=copy.deepcopy(self.pointer()['local_review']);reference=old['latest_local']
        review.continue_review(self.lab,max_batches=1,byte_budget=1)
        self.assertFalse(review._prune(self.lab,reference,old))
        self.assertTrue((self.lab.root/'objects'/reference['name']).exists())
    def test_wrong_plan_id_refused(self):
        review.status(self.lab);self.change(lambda s:s['local_review'].update(plan_id='another-plan'))
        with self.assertRaisesRegex(core.RepairError,'binding_conflict'):review.status(self.lab)
    def test_missing_seed_not_replaced_with_unreferenced_newer_checkpoint(self):
        review.status(self.lab);copy_path=self.seed.with_name('local-casc-evidence-'+os.urandom(16).hex()+'.sqlite');copy_path.write_bytes(self.seed.read_bytes());self.seed.unlink()
        with self.assertRaises((OSError,core.RepairError)):review.status(self.lab)
    def test_plan_change_even_same_plan_id_refused(self):
        review.status(self.lab);c=sqlite3.connect(self.plan)
        try:c.execute('UPDATE plan SET decoded_size=decoded_size+1');c.commit()
        finally:c.close()
        with self.assertRaisesRegex(core.RepairError,'referenced_file_changed'):review.continue_review(self.lab)
    def test_real_child_exit_after_durable_checkpoint_resume(self):
        script="""import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import local_review as r,repair_core as c
lab=c.Lab(Path(sys.argv[2]))
def notify(e):
 if e['stage']=='local_checkpoint_saved':os._exit(76)
r.continue_review(lab,max_batches=3,max_candidates=1,notify=notify)
"""
        done=subprocess.run([sys.executable,'-B','-c',script,str(Path(review.__file__).parent),str(self.lab.root)],capture_output=True)
        self.assertEqual(done.returncode,76,done.stderr.decode())
        self.assertEqual(self.current()['candidate_rows_completed'],2)
        r=review.continue_review(self.lab,max_batches=2,max_candidates=1);self.assertEqual(r['local_verification_summary']['candidate_rows_completed'],3)

if __name__=='__main__':unittest.main()
