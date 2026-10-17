"""SYNTHETIC metadata only. No actual user game/Lab/Download bytes tested."""
from pathlib import Path
from unittest.mock import patch
import hashlib,io,json,os,random,sqlite3,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scope_review_tests'))
from test_saved_scope_review import Integration as FixtureBase,PROFILE,manifest
from test_pinned_download_model import fixture_tags,model_for
import saved_object_review as o
import saved_scope_review as s
import pinned_download_model as m
import source_binding as b

def raw_manifest(entries=None,n=8):
    raw=manifest(n=n,version=1,tags=fixture_tags())
    if entries is None:entries=[(1,10),(1,10),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]
    assert len(entries)==n
    return raw[:11]+b''.join(k.to_bytes(16,'big')+size.to_bytes(5,'big')+b'\x02' for k,size in entries)+raw[11+n*22:]
def selected(raw):
    sink=[];r=s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None)
    q=s.parse_manifest(r,PROFILE,observe_unresolved=True,pinned_model=model_for(raw),_selection_sink=sink.append)
    return sink[0],q

class Collector(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.db=o.open_work(Path(self.tmp.name)/'work.sqlite',lambda:None)
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def collect(self,raw=None,selection=None,check=lambda:None):
        raw=raw or raw_manifest();selection=selection or selected(raw)[0]
        return o.collect(self.db,io.BytesIO(raw),len(raw),selection,check)
    def test_deduplicates_selected_records_only(self):
        q,r=self.collect();self.assertEqual(q['selected_records'],4);self.assertEqual(q['unique_ekeys'],3);self.assertEqual(q['duplicate_selected_records'],1)
        self.assertEqual([int.from_bytes(r[0],'big') for r in self.db.execute('SELECT ekey FROM objects')],[1,7,8])
    def test_selected_size_conflict_not_summed_or_hidden(self):
        raw=raw_manifest([(1,10),(1,11),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);q,_=self.collect(raw)
        self.assertEqual(q['unique_ekeys_with_conflicting_manifest_sizes'],1);self.assertEqual(self.db.execute('SELECT lo,hi,records FROM objects WHERE ekey=?',((1).to_bytes(16,'big'),)).fetchone(),(10,11,2))
    def test_unselected_conflict_outside_explicit_selected_scope(self):
        raw=raw_manifest([(1,10),(1,10),(1,999),(4,40),(5,50),(6,60),(7,70),(8,80)]);q,_=self.collect(raw);self.assertEqual(q['unique_ekeys_with_conflicting_manifest_sizes'],0)
    def test_zero_size_remains_unresolved(self):
        raw=raw_manifest([(1,0),(1,0),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);q,_=self.collect(raw);self.assertEqual(q['unique_ekeys_with_zero_manifest_size'],1)
    def test_all_empty_selection(self):
        raw=raw_manifest();sel=selected(raw)[0];sel['mask']=b'\0';q,_=self.collect(raw,sel);self.assertEqual(q['selected_records'],0);self.assertEqual(q['unique_ekeys'],0)
    def test_complete_second_raw_digest(self):
        raw=raw_manifest();q,r=self.collect(raw);self.assertEqual(r.used,len(raw));self.assertEqual(r.md5.hexdigest(),hashlib.md5(raw).hexdigest());self.assertEqual(r.sha.hexdigest(),hashlib.sha256(raw).hexdigest())
    def test_cancel_bounded(self):
        def stop():raise b.BindingError('cancelled')
        with self.assertRaises(b.BindingError):self.collect(check=stop)
    def test_truncated_second_pass(self):
        raw=raw_manifest();sel=selected(raw)[0]
        with self.assertRaises(b.BindingError):o.collect(self.db,io.BytesIO(raw[:-1]),len(raw),sel,lambda:None)
    def test_selection_mask_shape(self):
        raw=raw_manifest();sel=selected(raw)[0];sel['mask']=b''
        with self.assertRaisesRegex(b.BindingError,'object_selection_shape'):self.collect(raw,sel)
    def test_selection_padding_rejected(self):
        raw=raw_manifest(n=7,entries=[(i+1,10) for i in range(7)]);sel=selected(raw)[0];sel['mask']=bytes([sel['mask'][0]|1])
        with self.assertRaisesRegex(b.BindingError,'object_selection_padding'):self.collect(raw,sel)
    def test_bad_record_offset(self):
        raw=raw_manifest();sel=selected(raw)[0];sel['record_offset']=15
        with self.assertRaises(b.BindingError):self.collect(raw,sel)
    def test_work_database_is_bounded(self):
        self.assertEqual(self.db.execute('PRAGMA max_page_count').fetchone()[0]*4096,o.MAX_WORK_DB_BYTES)
    def test_source_autoindex_disabled(self):self.assertEqual(self.db.execute('PRAGMA automatic_index').fetchone()[0],0)
    def test_private_callback_not_public_field(self):
        raw=raw_manifest();sel,q=selected(raw);self.assertEqual(hashlib.sha256(sel['mask']).hexdigest(),q['selected_record_bitmap_sha256']);self.assertNotIn('mask',json.dumps(q))
    def test_callback_not_given_for_generic_model(self):
        raw=manifest();sink=[];s.parse_manifest(s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None),PROFILE,_selection_sink=sink.append);self.assertEqual(sink,[])
    def test_callback_not_given_for_wrong_pinned_identity(self):
        from dataclasses import replace
        raw=raw_manifest();sink=[]
        with self.assertRaises(b.BindingError):s.parse_manifest(s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None),PROFILE,pinned_model=replace(model_for(raw),sha256='0'*64),_selection_sink=sink.append)
        self.assertEqual(sink,[])
    def test_callback_not_given_for_unresolved_requested_profile(self):
        raw=raw_manifest();sink=[];s.parse_manifest(s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None),dict(PROFILE,architecture='ARM64'),observe_unresolved=True,pinned_model=model_for(raw),_selection_sink=sink.append);self.assertEqual(sink,[])
    def test_sql_progress_cancel(self):
        self.db.close()
        calls=[0]
        def stop():
            calls[0]+=1
            if calls[0]>1:raise b.BindingError('cancelled')
        self.db=o.open_work(Path(self.tmp.name)/'second.sqlite',stop)
        with self.assertRaises(sqlite3.OperationalError):self.db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT sum(x) FROM n').fetchone()
    def test_random_selected_duplicates_independent_dictionary_oracle(self):
        rng=random.Random(9824)
        for _ in range(128):
            self.db.execute('DELETE FROM objects');self.db.commit()
            entries=[(rng.randint(1,4),rng.randint(0,3)) for _ in range(8)]
            raw=raw_manifest(entries);q,_=self.collect(raw)
            expected={}
            # Independently fixed selected fixture ordinals, not the mask code.
            for index in (0,1,6,7):
                key,size=entries[index];expected.setdefault(key,[]).append(size)
            self.assertEqual(q['selected_records'],4);self.assertEqual(q['unique_ekeys'],len(expected))
            self.assertEqual(q['unique_ekeys_with_conflicting_manifest_sizes'],sum(len(set(sizes))>1 for sizes in expected.values()))
            observed={int.from_bytes(key,'big'):(lo,hi,count) for key,lo,hi,count in self.db.execute('SELECT * FROM objects')}
            self.assertEqual(observed,{key:(min(sizes),max(sizes),len(sizes)) for key,sizes in expected.items()})
    def test_record_versions_and_flags_second_pass(self):
        for version,flags,checksum in [(1,0,0),(2,4,1),(3,4,1)]:
            self.db.execute('DELETE FROM objects');self.db.commit()
            raw=manifest(version=version,flags=flags,checksum=checksum,tags=fixture_tags())
            q,r=self.collect(raw)
            self.assertEqual(q['selected_records'],4);self.assertEqual(q['unique_ekeys'],4);self.assertEqual(r.used,len(raw))

class Coordinates(unittest.TestCase):
    def setUp(self):self.snap={'files':{'data.000':[0,0,668,0,1]}};self.row=[1,10,0,510,'data.000',668,0]
    def ok(self):return o.coordinate_ok(self.row,10,self.snap)
    def test_valid_metadata_only(self):self.assertTrue(self.ok())
    def test_negative_offset(self):self.row[3]=-1;self.assertFalse(self.ok())
    def test_out_of_bounds(self):self.row[3]=660;self.assertFalse(self.ok())
    def test_ambiguous_archive(self):self.row[6]=1;self.assertFalse(self.ok())
    def test_wrong_archive_size(self):self.row[5]=669;self.assertFalse(self.ok())
    def test_outside_saved_files(self):self.row[4]='data.001';self.assertFalse(self.ok())
    def test_path_not_allowed(self):self.row[4]='../data.000';self.assertFalse(self.ok())
    def test_text_size_not_coerced(self):self.row[1]='10';self.assertFalse(self.ok())
    def test_negative_archive_id(self):self.row[2]=-1;self.assertFalse(self.ok())

class Integration(unittest.TestCase):
    setUpClass=classmethod(FixtureBase.setUpClass.__func__)
    setUp=FixtureBase.setUp;tearDown=FixtureBase.tearDown;rebind_test_manifest=FixtureBase.rebind_test_manifest
    def prepare(self,entries=None):
        raw=raw_manifest(entries);self.rebind_test_manifest(raw);self.path.write_bytes(raw);return model_for(raw)
    def execute(self,model=None,output=None,**kwargs):
        real=s.a.config
        def config(raw,key):return dict(real(raw,key),**self.config_data)
        with patch.object(b,'load_metadata',return_value=self.bound_metadata),patch.object(s.a,'config',side_effect=config),patch.object(m,'for_ckey',return_value=model):
            return o.run(self.f.lab,self.audit,self.game,output or self.root/'new',**kwargs)
    def candidate(self,k,size,offset=510,archive_id=0):
        self.f.edit(self.f.inv,'INSERT INTO candidates(ekey,archive_id,payload_offset,encoded_size) VALUES (?,?,?,?)',(k.to_bytes(16,'big'),archive_id,offset,size))
    def assert_no_work(self):self.assertFalse(list((self.root/'new').glob('private-work-*')))
    def test_full_success_counts_and_unknown_not_missing(self):
        model=self.prepare();self.candidate(1,10);self.candidate(7,999)
        q,final=self.execute(model);z=q['object_projection'];self.assertEqual(q['status'],'bound_selected_unique_objects_inventory_projection_complete');self.assertEqual(z['unique_ekeys'],3);self.assertEqual(z['unique_ekeys_by_metadata_state'][o.CATEGORIES[5]],1);self.assertEqual(z['unique_ekeys_by_metadata_state'][o.CATEGORIES[3]],1);self.assertEqual(z['unique_ekeys_by_metadata_state'][o.CATEGORIES[2]],1);self.assertEqual(json.loads(final.read_text()),q);self.assert_no_work()
    def test_duplicate_size_conflict_is_its_own_state(self):
        model=self.prepare([(1,10),(1,11),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);self.candidate(1,10);q,_=self.execute(model);self.assertEqual(q['object_projection']['unique_ekeys_by_metadata_state'][o.CATEGORIES[0]],1)
    def test_zero_size_never_matches_installed_proof(self):
        model=self.prepare([(1,0),(1,0),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);self.candidate(1,0);q,_=self.execute(model);self.assertEqual(q['object_projection']['unique_ekeys_by_metadata_state'][o.CATEGORIES[1]],1)
    def test_bad_coordinates_are_not_usable(self):
        model=self.prepare();self.candidate(1,10,offset=9999);q,_=self.execute(model);self.assertEqual(q['object_projection']['unique_ekeys_by_metadata_state'][o.CATEGORIES[4]],1)
    def test_multiple_candidates_do_not_double_count_objects(self):
        model=self.prepare();self.candidate(1,10);self.candidate(1,10);q,_=self.execute(model);z=q['object_projection'];self.assertEqual(z['unique_ekeys_by_metadata_state'][o.CATEGORIES[5]],1);self.assertEqual(z['unique_ekeys_with_multiple_inventory_candidates'],1)
    def test_alias_limit_stops_and_removes_work(self):
        model=self.prepare()
        for _ in range(65):self.candidate(1,10)
        with self.assertRaisesRegex(b.BindingError,'object_inventory_alias_limit'):self.execute(model)
        self.assert_no_work();self.assertFalse((self.root/'new/Report').exists())
    def test_join_row_limit_stops(self):
        model=self.prepare();self.candidate(1,10)
        with patch.object(o,'MAX_JOIN_ROWS',0):
            with self.assertRaisesRegex(b.BindingError,'object_inventory_join_row_limit'):self.execute(model)
        self.assert_no_work()
    def test_exact_inventory_reference_required(self):
        model=self.prepare()
        with patch.object(o,'exact_inventory',side_effect=b.BindingError('object_exact_saved_inventory_reference_required')):
            with self.assertRaises(b.BindingError):self.execute(model)
        self.assert_no_work()
    def test_readonly_inventory_never_migrated(self):
        model=self.prepare();before=self.f.inv.read_bytes();self.execute(model);self.assertEqual(before,self.f.inv.read_bytes());self.assertFalse(Path(str(self.f.inv)+'-journal').exists())
    def test_missing_existing_index_refused(self):
        model=self.prepare();self.f.edit(self.f.inv,'DROP INDEX candidate_key')
        with self.assertRaisesRegex(b.BindingError,'existing_source_ekey_index_required'):self.execute(model)
        self.assertFalse((self.root/'new').exists())
    def test_no_network_archive_or_extra_game_metadata_reads(self):
        model=self.prepare();original=Path.open;opened=[]
        def check(path,*args,**kwargs):
            if path==self.f.archive:raise AssertionError('archive read forbidden')
            if self.game in path.parents:opened.append(path)
            return original(path,*args,**kwargs)
        import socket
        with patch.object(Path,'open',check),patch.object(socket,'socket',side_effect=AssertionError('network forbidden')),patch.object(s.a.Fetcher,'get',side_effect=AssertionError('network forbidden')):q,_=self.execute(model)
        self.assertEqual(opened,[self.game/'.build.info',self.config]);self.assertEqual(q['scope']['archive_payload_bytes_read'],0);self.assertEqual(q['network_requests'],0)
    def test_input_bytes_and_fingerprints_unchanged(self):
        from fixtures import contents
        model=self.prepare();before=(contents(self.f.lab),contents(self.game));self.execute(model);self.assertEqual(before,(contents(self.f.lab),contents(self.game)))
    def test_total_metadata_bytes_two_passes_not_two_budgets(self):
        model=self.prepare();q,_=self.execute(model);self.assertEqual(q['scope']['saved_download_metadata_bytes_read'],2*len(self.raw));self.assertEqual(q['scope']['saved_download_metadata_total_read_max_bytes'],256*1024**2)
    def test_cumulative_budget_rejected_before_work(self):
        model=self.prepare()
        with patch.object(o,'MAX_METADATA_READ',len(self.raw)):
            with self.assertRaisesRegex(b.BindingError,'object_metadata_read_budget'):self.execute(model)
        self.assertFalse((self.root/'new').exists())
    def test_no_selected_keys_paths_or_game_health_claims(self):
        model=self.prepare();q,_=self.execute(model);text=json.dumps(q);self.assertNotIn(str(self.root),text);self.assertNotIn('PRIVATE',text);self.assertNotIn('acct-',text);self.assertFalse(q['installation_ready']);self.assertFalse(q['fresh_local_content_verified']);self.assertFalse(q['actual_required_install_set_known']);self.assertIsNone(q['required_network_download_bytes']);self.assertFalse(q['object_projection']['prior_evidence_success_flags_used'])
    def test_missing_cache_unknown_and_no_private_database(self):
        q,_=self.execute(None);self.assertEqual(q['status'],'bound_download_metadata_unavailable');self.assertIsNone(q['object_projection']);self.assert_no_work()
    def test_generic_selection_does_not_authorize_object_projection(self):
        self.path.write_bytes(self.raw);q,_=self.execute(None);self.assertEqual(q['status'],'bound_download_diagnostic_projection_complete');self.assertFalse(q['selected_unique_object_projection_computed']);self.assertIsNone(q['object_projection'])
    def test_cancel_no_report(self):
        model=self.prepare()
        with self.assertRaises(b.BindingError):self.execute(model,cancel=lambda:True)
        self.assertFalse((self.root/'new').exists())
    def test_cancel_during_collection_removes_work(self):
        model=self.prepare();stop=[False]
        def progress(stage):
            if stage=='deduplicate_selected_records':stop[0]=True
        with self.assertRaises(b.BindingError):self.execute(model,cancel=lambda:stop[0],progress=progress)
        self.assert_no_work();self.assertFalse((self.root/'new/Report').exists())
    def test_second_pass_hash_mismatch_no_report(self):
        model=self.prepare();original=o.collect
        def change(*args,**kwargs):
            q,r=original(*args,**kwargs);r.sha=hashlib.sha256(b'bad');return q,r
        with patch.object(o,'collect',side_effect=change):
            with self.assertRaisesRegex(b.BindingError,'object_second_pass_content_identity_mismatch'):self.execute(model)
        self.assert_no_work()
    def test_input_changed_between_passes_rejected(self):
        model=self.prepare()
        def progress(stage):
            if stage=='prepare_private_workspace':self.path.write_bytes(self.raw+b'x')
        with self.assertRaises(b.BindingError):self.execute(model,progress=progress)
        self.assertFalse((self.root/'new').exists())
    def test_changed_inventory_during_join_rejected(self):
        model=self.prepare()
        def progress(stage):
            if stage=='join_saved_inventory':self.f.edit(self.f.inv,'INSERT INTO candidates(ekey) VALUES (?)',(bytes(16),))
        with self.assertRaises(b.BindingError):self.execute(model,progress=progress)
        self.assert_no_work()
    def test_input_changed_before_publication_rejected(self):
        model=self.prepare()
        def progress(stage):
            if stage=='prepare_report_output':self.config.write_bytes(b'changed')
        with self.assertRaises(b.BindingError):self.execute(model,progress=progress)
        self.assert_no_work();self.assertFalse((self.root/'new/Report/SCOPE-REVIEW-to-share.json').exists())
    def test_postpublication_change_removes_own_report(self):
        model=self.prepare()
        def progress(stage):
            if stage=='postpublication_recheck':self.config.write_bytes(b'changed')
        with self.assertRaises(b.BindingError):self.execute(model,progress=progress)
        self.assertFalse((self.root/'new/Report/SCOPE-REVIEW-to-share.json').exists());self.assert_no_work()
    def test_racing_report_is_preserved(self):
        model=self.prepare()
        def race(temp,final):final.write_text('OTHER');raise FileExistsError()
        with patch.object(s.p,'publish_noreplace',side_effect=race):
            with self.assertRaises(FileExistsError):self.execute(model)
        self.assertEqual((self.root/'new/Report/SCOPE-REVIEW-to-share.json').read_text(),'OTHER');self.assert_no_work()
    def test_existing_output_not_deleted(self):
        model=self.prepare();out=self.root/'new';out.mkdir();(out/'keep').write_text('KEEP')
        with self.assertRaisesRegex(b.BindingError,'object_new_output_required'):self.execute(model)
        self.assertEqual((out/'keep').read_text(),'KEEP')
    def test_output_under_inputs_or_parent_rejected(self):
        model=self.prepare()
        for out in [self.game/'new',self.f.lab/'new',self.audit/'new',self.root]:
            with self.subTest(out=out):
                with self.assertRaises(b.BindingError):self.execute(model,output=out)
    def test_output_symlink_rejected(self):
        model=self.prepare();(self.root/'link').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(b.BindingError):self.execute(model,output=self.root/'link/new')
    def test_unknown_errors_do_not_leak_paths(self):
        error=o.public_error(OSError(22,'SECRET_PATH'), 'join_saved_inventory');self.assertEqual(error['scope_review_version'],o.VERSION);self.assertEqual(error['stage'],'join_saved_inventory');self.assertNotIn('SECRET',json.dumps(error))
    def test_no_private_work_remaining_when_publishing(self):
        model=self.prepare()
        def progress(stage):
            if stage=='prepare_report_output':self.assert_no_work()
        self.execute(model,progress=progress)
    def test_same_size_rewrite_with_restored_stat_rejected_by_second_hash(self):
        model=self.prepare()
        def progress(stage):
            if stage=='prepare_private_workspace':
                stat=self.path.stat();changed=bytearray(self.raw);changed[11+2*22+17]^=1
                self.path.write_bytes(changed);os.utime(self.path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
        with self.assertRaisesRegex(b.BindingError,'object_second_pass_content_identity_mismatch'):self.execute(model,progress=progress)
        self.assert_no_work();self.assertFalse((self.root/'new/Report').exists())
    def test_random_inventory_states_independent_oracle(self):
        model=self.prepare();rng=random.Random(70391)
        for case in range(24):
            self.f.edit(self.f.inv,'DELETE FROM candidates WHERE id>1')
            expected={name:0 for name in o.CATEGORIES};candidate_rows=0
            for key,size in ((1,10),(7,70),(8,80)):
                state=rng.choice(['none','wrong_size','bad_bounds','valid','valid_alias'])
                category={'none':o.CATEGORIES[2],'wrong_size':o.CATEGORIES[3],'bad_bounds':o.CATEGORIES[4],'valid':o.CATEGORIES[5],'valid_alias':o.CATEGORIES[5]}[state]
                expected[category]+=1
                if state!='none':
                    self.candidate(key,size+1 if state=='wrong_size' else size,offset=9999 if state=='bad_bounds' else 510);candidate_rows+=1
                    if state=='valid_alias':self.candidate(key,size,offset=520);candidate_rows+=1
            q,_=self.execute(model,output=self.root/('case-'+str(case)))
            self.assertEqual(q['object_projection']['unique_ekeys_by_metadata_state'],expected)
            self.assertEqual(q['object_projection']['inventory_candidate_rows_examined'],candidate_rows)
    def test_new_output_and_work_limit_failure_does_not_touch_lab(self):
        from fixtures import contents
        model=self.prepare();before=contents(self.f.lab)
        with patch.object(o,'open_work',side_effect=sqlite3.OperationalError('PRIVATE_PATH disk full')):
            with self.assertRaisesRegex(b.BindingError,'object_private_or_readonly_database_stopped_safely'):self.execute(model)
        self.assert_no_work();self.assertEqual(contents(self.f.lab),before)
    def test_opaque_consistent_saved_binding_fields_preserved_not_guessed(self):
        model=self.prepare();binding=dict(self.target,opaque_saved_field='opaque-not-exported')
        for path in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):
            self.f.edit(path,'UPDATE metadata SET value=? WHERE name=?',(json.dumps(binding),'target_binding'))
        q,_=self.execute(model)
        self.assertTrue(q['selected_unique_object_projection_computed']);self.assertNotIn('opaque-not-exported',json.dumps(q))

del FixtureBase
