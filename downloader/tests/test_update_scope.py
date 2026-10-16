import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import content_plan
import downloader_controller as controller
import installed_metadata
import local_casc as local
import metadata_delta
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse
import update_scope as scope
import test_download_inventory as di
import test_metadata_delta as mt


class ProfileTests(unittest.TestCase):
    def profile(self,tags):return scope.installed_profile(type('Identity',(),{'row':{'tags':tags}})())
    def test_supported_exact_installed_profile(self):
        p=self.profile('Windows x86_64 EU enUS speech:Windows x86_64 EU enUS text')
        self.assertEqual(p,content_plan.Profile(('enUS',)))
    def test_locale_union_preserves_multiple_languages(self):
        self.assertEqual(self.profile('Windows x86_64 EU enUS speech:Windows x86_64 EU frFR text').locales,('enUS','frFR'))
    def test_categories_not_required(self):self.profile('Windows x86_64 EU enUS')
    def test_unknown_tokens_block_without_leaking(self):
        with self.assertRaisesRegex(core.RepairError,'unknown_installed_tag') as e:self.profile('Windows x86_64 EU enUS SECRET_ACCOUNT')
        self.assertNotIn('SECRET_ACCOUNT',str(e.exception))
    def test_multiple_platforms_not_flattened(self):
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):self.profile('Windows OSX x86_64 EU enUS')
    def test_multiple_architectures_not_guessed(self):
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):self.profile('Windows x86_32 x86_64 EU enUS')
    def test_multiple_regions_not_guessed(self):
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):self.profile('Windows x86_64 EU US enUS')
    def test_missing_dimension_stops(self):
        for s in ('Windows x86_64 enUS','Windows EU enUS','x86_64 EU enUS','Windows x86_64 EU',''):
            with self.assertRaises(core.RepairError):self.profile(s)
    def test_unsupported_profile_no_fallback(self):
        for s in ('OSX x86_64 EU enUS','Windows x86_32 EU enUS','Windows x86_64 US enUS','Windows x86_64 EU enGB'):
            with self.assertRaises(core.RepairError):self.profile(s)
    def test_empty_clause_not_ignored(self):
        for s in ('Windows x86_64 EU enUS:',':Windows x86_64 EU enUS','Windows x86_64 EU enUS::text'):
            with self.assertRaises(core.RepairError):self.profile(s)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve()
        self.lab=core.Lab.create(self.base/'lab');self.work=core.Lab.create(self.base/'work')
        # Keys a,b retained; c added encoded locally; d added decoded only;
        # e old catalogue but newly included in profile; f other locale excluded;
        # g no dimension tag membership => shared and MUST remain selected.
        self.old_entries=[(bytes([i])*16,100*i,0) for i in (1,2,5,6)]
        self.new_entries=[(bytes([i])*16,100*i,0) for i in range(1,8)]
        def tags(n,locale_members):
            return [('Windows',1,list(range(n))),('OSX',1,[]),('x86_64',2,list(range(n))),('x86_32',2,[]),
                    ('enUS',3,locale_members),('frFR',3,[i for i in range(n) if i not in locale_members and i!=n-1]),
                    ('EU',4,list(range(n))),('US',4,[]),('speech',5,[0]),('text',5,[1]),('Alternate',0x4000,[2])]
        self.old_data=di.fixture(self.old_entries,tags(4,[0,1]))
        self.new_data=di.fixture(self.new_entries,tags(7,[0,1,2,3,4]))
        self.old_ck=hashlib.md5(self.old_data).hexdigest();self.ck=hashlib.md5(self.new_data).hexdigest()
        self.binding=dict(product='wow',region='eu',version='12.1.5.70391',build_config='a'*32,cdn_config='b'*32,download_ckey=self.ck)
        self.old=self.inv(self.old_data,self.old_ck,dict(self.binding,version='12.1.0.69933'))
        self.new=self.inv(self.new_data,self.ck,self.binding)
        self.plan,self.queue=self.make_queue()
        self.net=patch.object(core.HTTPS,'open',side_effect=AssertionError('network forbidden'));self.net.start();self.addCleanup(self.net.stop)
    def inv(self,data,ck,binding):
        p=self.work.root/'objects'/(ck+'-'+str(len(data))+'.decoded');p.write_bytes(data)
        return metadata_delta.inventory(self.work,p,ck,binding)
    def make_queue(self):
        with store.Writer(self.lab,'content-plan',threading.Event()) as out:
            out.db.execute('CREATE TABLE plan(ekey BLOB PRIMARY KEY,encoded_size INTEGER)')
            out.db.executemany('INSERT INTO plan VALUES (?,?)',[(k,s) for k,s,_ in self.new_entries]);out.metadata('target_binding',self.binding);out.metadata('plan_id',out.path.stem)
        plan=out.path
        with store.Writer(self.lab,'acquisition-queue',threading.Event()) as out:
            out.db.execute('CREATE TABLE queue(ekey BLOB PRIMARY KEY,encoded_size INTEGER,availability TEXT,conditional_transfer INTEGER)')
            states=['encoded_available','conditional_download','encoded_available','decoded_content_only','unresolved_plan','conditional_download','conditional_download']
            out.db.executemany('INSERT INTO queue VALUES (?,?,?,?)',[(k,s,a,int(a in ('conditional_download','decoded_content_only'))) for (k,s,_),a in zip(self.new_entries,states)])
            out.metadata('target_binding',self.binding);out.metadata('source_plan_id',plan.stem)
            out.metadata('source_snapshot',{'files':{},'local_snapshots':[]});out.metadata('private_evidence_inputs',{});out.metadata('queue_summary',{})
        return plan,out.path
    def runscope(self,**kw):return scope.project(self.work,self.old,self.new,self.lab,self.plan,self.queue,content_plan.Profile(('enUS',)),**kw)
    def mutate_queue(self,sql,args=()):
        db=sqlite3.connect(self.queue);db.execute(sql,args);db.commit();db.close()
    def test_scope_partitions_changed_retained_and_reused_exactly_once(self):
        r=self.runscope();groups={(x['change_class'],x['availability']):x for x in r['breakdown']}
        self.assertEqual(r['profile_selected_unique_objects'],6)
        self.assertEqual(r['excluded_from_this_profile_projection_objects'],1)
        self.assertEqual(r['newly_selected_without_encoded_proof_objects'],3) # d,e,g; c already encoded
        self.assertEqual(r['newly_selected_without_encoded_proof_full_bytes'],1600)
        self.assertEqual(r['retained_profile_without_encoded_proof_objects'],1) # b still unknown locally
        self.assertEqual(groups['common_catalogue_new_to_profile','unresolved_plan']['objects'],1)
        self.assertEqual(groups['added_to_catalogue','encoded_available']['full_encoded_bytes'],300)
        self.assertTrue(r['independent_reconciliation_passed'])
    def test_old_catalogue_is_not_possession_proof(self):
        r=self.runscope();self.assertEqual(r['retained_profile_without_encoded_proof_objects'],1)
        self.assertIsNone(r['required_network_download_bytes']);self.assertFalse(r['installation_ready'])
    def test_decoded_only_not_counted_as_encoded(self):
        r=self.runscope();rows=[x for x in r['breakdown'] if x['availability']=='decoded_content_only']
        self.assertEqual(rows[0]['full_encoded_bytes'],400);self.assertEqual(rows[0]['conditional_full_encoded_body_bytes'],400)
    def test_category_alternate_and_shared_records_not_filtered(self):
        r=self.runscope();self.assertEqual(r['profile_selected_unique_objects'],6)
        self.assertFalse(r['category_and_alternate_tags_used_for_exclusion']);self.assertTrue(r['unclassified_records_preserved_per_dimension'])
    def test_inputs_and_session_not_modified(self):
        state=self.lab.root/'objects'/'downloader-ui-session.json';state.write_bytes(b'PRIVATE existing session')
        paths=[self.old,self.new,self.plan,self.queue,state];before={p:p.read_bytes() for p in paths}
        self.runscope();self.assertEqual(before,{p:p.read_bytes() for p in paths})
    def test_no_asset_reads_or_network(self):
        r=self.runscope();self.assertFalse(r['asset_payloads_reread']);self.assertEqual(r['network_requests'],0)
    def test_scope_not_an_operational_acquisition_queue(self):
        self.runscope();p=list((self.work.root/'objects').glob('update-scope-*.sqlite'))[0]
        with store.input_db(self.work,p) as (db,_):
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='queue'").fetchone())
    def test_missing_target_queue_row_blocks(self):
        self.mutate_queue('DELETE FROM queue WHERE ekey=?',(bytes([1])*16,))
        with self.assertRaisesRegex(core.RepairError,'queue_missing'):self.runscope()
    def test_size_conflict_blocks_not_extra_download(self):
        self.mutate_queue('UPDATE queue SET encoded_size=encoded_size+1')
        with self.assertRaisesRegex(core.RepairError,'size_conflict'):self.runscope()
    def test_unknown_availability_blocks(self):
        self.mutate_queue("UPDATE queue SET availability='old_success_flag'")
        with self.assertRaisesRegex(core.RepairError,'unknown_queue'):self.runscope()
    def test_target_download_ckey_binding_conflict(self):
        db=sqlite3.connect(self.new);db.execute("UPDATE metadata SET value=? WHERE name='manifest_ckey'",(json.dumps('e'*32),));db.commit();db.close()
        with self.assertRaisesRegex(core.RepairError,'manifest_binding'):self.runscope()
    def test_queue_target_binding_conflict(self):
        self.mutate_queue("UPDATE metadata SET value=? WHERE name='target_binding'",(json.dumps(dict(self.binding,version='wrong')),))
        with self.assertRaisesRegex(core.RepairError,'binding_conflict'):self.runscope()
    def test_pre_cancel_no_scope_published(self):
        e=threading.Event();e.set()
        with self.assertRaises(core.Cancelled):self.runscope(cancel=e)
        self.assertFalse(list((self.work.root/'objects').glob('update-scope-*.sqlite')))
    def test_cancel_during_selection_no_partial_published(self):
        e=threading.Event()
        def notice(_):e.set()
        with self.assertRaises(core.Cancelled):self.runscope(cancel=e,notify=notice)
        self.assertFalse(list((self.work.root/'objects').glob('update-scope-*')))
    def test_queue_source_changes_blocks_publication(self):
        source=self.base/'proof';source.write_bytes(b'before');fp=list(core.fingerprint(source.stat()))
        self.mutate_queue("UPDATE metadata SET value=? WHERE name='source_snapshot'",(json.dumps({'files':{str(source):fp},'local_snapshots':[]}),))
        done=[]
        def notify(e):
            if not done:source.write_bytes(b'changed');done.append(True)
        with self.assertRaisesRegex(core.RepairError,'source_changed'):self.runscope(notify=notify)
        self.assertFalse(list((self.work.root/'objects').glob('update-scope-*')))
    def test_low_space_fails_before_scope(self):
        with patch.object(scope.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
            with self.assertRaisesRegex(core.RepairError,'insufficient_workspace'):self.runscope()
    def test_tag_kind_change_not_guessed(self):
        db=sqlite3.connect(self.new);db.execute("UPDATE tags SET kind=4 WHERE name='enUS'");db.commit();db.close()
        with self.assertRaisesRegex(core.RepairError,'kind_model'):self.runscope()
    def test_missing_requested_tag_no_fallback(self):
        db=sqlite3.connect(self.new);db.execute("DELETE FROM tags WHERE name='enUS'");db.commit();db.close()
        with self.assertRaisesRegex(core.RepairError,'tag_missing'):self.runscope()
    def test_public_summary_whitelist(self):
        text=json.dumps(self.runscope());self.assertNotIn(str(self.base),text)
        self.assertNotIn('ekey',text);self.assertNotIn('PRIVATE',text)
    def test_duplicate_selected_records_deduplicated(self):
        data=di.fixture(self.new_entries+[self.new_entries[0]],[])
        ck=hashlib.md5(data).hexdigest();binding=dict(self.binding,download_ckey=ck)
        # Preserve all original tags with added ordinal selected for every dimension.
        tags=[('Windows',1,list(range(8))),('x86_64',2,list(range(8))),('enUS',3,list(range(8))),('EU',4,list(range(8)))]
        data=di.fixture(self.new_entries+[self.new_entries[0]],tags);ck=hashlib.md5(data).hexdigest();binding['download_ckey']=ck
        self.new=self.inv(data,ck,binding)
        for p in (self.plan,self.queue):
            db=sqlite3.connect(p);db.execute("UPDATE metadata SET value=? WHERE name='target_binding'",(json.dumps(binding),));db.commit();db.close()
        self.assertEqual(self.runscope()['profile_selected_unique_objects'],7)


class EntrypointTests(unittest.TestCase):
    setUp=mt.PlannerTests.setUp
    cache_old=mt.PlannerTests.cache_old
    source_hashes=mt.PlannerTests.source_hashes
    def queue(self):
        # Use the real reuse pipeline to produce a schema-valid pinned queue.
        _,inv=reuse.inventory(self.lab,self.plan);_,ev=reuse.verify_batch(self.lab,self.plan,inv)
        _,q=reuse.make_queue(self.lab,self.plan,inv,ev)
        db=sqlite3.connect(q)
        try:
            snap=local._snapshot(self.storage);db.execute("UPDATE metadata SET value=? WHERE name='source_snapshot'",(json.dumps({'files':{},'local_snapshots':[snap]}),));db.commit()
        finally:db.close()
        controller.save_state(self.lab,self.plan,q);return q
    def tagged(self):
        tags=[('Windows',1,[0,1]),('x86_64',2,[0,1]),('enUS',3,[0,1]),('EU',4,[0,1])]
        data=di.fixture([(b'b'*16,200,1),(b'c'*16,300,0)],tags)
        # Use same catalogue for old & target to test zero logical delta doesn't
        # mask missing local proof; this fixture is not an actual user build.
        ck=hashlib.md5(data).hexdigest();self.old_data=data;self.old_ck=ck
        from test_repair_core import encoded
        blob,ek=encoded(data,table=True)
        self.build=('build-uid = wow\nbuild-name = WOW-70390patch12.1.5_Retail\ndownload = %s %s\ndownload-size = %d %d\n'%(ck,ek,len(data),len(blob))).encode()
        bk=hashlib.md5(self.build).hexdigest();p=self.game/'Data'/'config'/bk[:2]/bk[2:4]/bk;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(self.build)
        (self.game/'.build.info').write_bytes(mt.info(bk));self.cache_old()
        self.target_cache.unlink();self.target_cache=self.lab.root/'objects'/(ck+'-'+str(len(data))+'.decoded');self.target_cache.write_bytes(data)
        db=sqlite3.connect(self.plan)
        try:self.binding=dict(self.binding,download_ckey=ck);db.execute("UPDATE metadata SET value=? WHERE name='target_binding'",(json.dumps(self.binding),));db.commit()
        finally:db.close()
    def test_real_entrypoint_zero_delta_is_not_zero_required_download(self):
        self.tagged();q=self.queue();before=self.source_hashes();state=self.state.read_bytes();queue_bytes=q.read_bytes()
        r=scope.plan_from_queue(self.lab,self.plan,q)
        self.assertEqual(r['logical_catalogue_delta']['added_encoded_keys'],0)
        self.assertEqual(r['update_scope']['retained_profile_without_encoded_proof_objects'],2)
        self.assertEqual(r['update_scope']['newly_selected_without_encoded_proof_objects'],0)
        self.assertIsNone(r['required_network_download_bytes']);self.assertFalse(r['installation_ready'])
        self.assertEqual(before,self.source_hashes());self.assertEqual(state,self.state.read_bytes());self.assertEqual(queue_bytes,q.read_bytes())
        self.assertEqual(len(list((self.lab.root/'objects').glob('Retail-Update-Scope-to-share-*.json'))),1)
    def test_unmerged_local_proofs_block_before_metadata_work(self):
        q=self.queue();d=core.load_json(self.state);d['local_review']={'merged_checkpoint':'old','latest_local':{'name':'new'}};core.atomic_json(self.state,d)
        with self.assertRaisesRegex(core.RepairError,'refresh_existing'):scope.plan_from_queue(self.lab,self.plan,q)
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')))
    def test_wrong_active_queue_not_accepted(self):
        q=self.queue();other=self.queue()
        with self.assertRaisesRegex(core.RepairError,'active_session'):scope.plan_from_queue(self.lab,self.plan,q)
    def test_unknown_profile_before_new_workspace(self):
        q=self.queue();(self.game/'.build.info').write_bytes(mt.info(self.bk,tags='Windows x86_64 EU enUS SECRET'))
        with self.assertRaisesRegex(core.RepairError,'unknown_installed_tag'):scope.plan_from_queue(self.lab,self.plan,q)
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')))
    def test_active_session_change_during_work_no_public_report(self):
        self.tagged();q=self.queue();done=[]
        def notify(e):
            if not done:core.atomic_json(self.state,{'concurrent':'change'});done.append(True)
        with self.assertRaisesRegex(core.RepairError,'active_session'):scope.plan_from_queue(self.lab,self.plan,q,notify=notify)
        self.assertFalse(list((self.lab.root/'objects').glob('Retail-Update-Scope-to-share-*.json')))
    def test_game_change_during_work_no_public_report(self):
        self.tagged();q=self.queue();done=[]
        def notify(e):
            if not done:self.archive.write_bytes(self.archive.read_bytes()+b'x');done.append(True)
        with self.assertRaisesRegex(core.RepairError,'changed'):scope.plan_from_queue(self.lab,self.plan,q,notify=notify)
        self.assertFalse(list((self.lab.root/'objects').glob('Retail-Update-Scope-to-share-*.json')))
