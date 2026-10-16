import hashlib,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import patch_audit as a
import source_binding as b

BINDING={'product':'wow','region':'eu','version':a.VERSION,'build_config':a.BUILD,'cdn_config':a.CDN,'download_ckey':'5beff4cf8122da27a6788d9062c8d3c2','download_ekey':'fa1124f7249c41d63eda566523dd7444'}
OPT=a.PatchOption('20'*16,4,'30'*16,3,'40'*16,100,0)

def writejson(p,obj):p.write_text(json.dumps(obj))

def dbfile(p,metadata,sql):
    db=sqlite3.connect(p)
    db.execute('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.executemany('INSERT INTO metadata VALUES (?,?)',[(k,json.dumps(v)) for k,v in metadata.items()])
    for statement,args in sql:db.execute(statement,args)
    db.commit();db.close()

class Fixture:
    def __init__(self,root,option=OPT):
        self.root=root;self.option=option
        self.lab=root/'lab';self.lab.mkdir();self.objects=self.lab/'objects';self.objects.mkdir()
        self.game=root/'source';self.game.mkdir();self.archive=self.game/'data.000';self.archive.write_bytes(b'XXXXX')
        self.audit=root/'audit';self.audit.mkdir()
        writejson(self.lab/'LAB-ONLY.json',{'format':'wow-repair-lab-1','id':'0'*32,'real_game_installation':False})
        self.plan=self.objects/('content-plan-'+'1'*32+'.sqlite')
        self.queue=self.objects/('acquisition-queue-'+'2'*32+'.sqlite')
        self.inv=self.objects/('local-casc-inventory-'+'3'*32+'.sqlite')
        self.ev=self.objects/('local-casc-evidence-'+'4'*32+'.sqlite')
        pid=self.plan.stem;sid='6'*32
        self.snapshot={'directory':str(self.game),'names':sorted(os.listdir(self.game)),'directory_identity':b.fp(self.game.stat()),'files':{'data.000':b.fp(self.archive.stat())}}
        common={'target_binding':BINDING,'source_plan_id':pid}
        ek=bytes.fromhex(option.source_ekey);ck=bytes.fromhex('77'*16)
        dbfile(self.plan,{'target_binding':BINDING,'plan_id':pid},[
            ('CREATE TABLE plan(ekey BLOB PRIMARY KEY,ckey BLOB,encoded_size INTEGER,decoded_size INTEGER,mapping_state TEXT,transfer_supported INTEGER)',()),
            ('INSERT INTO plan VALUES (?,?,?,?,?,?)',(bytes.fromhex('55'*16),bytes.fromhex(option.target_ckey),5,option.target_size,'mapped',1)),
            ('INSERT INTO plan VALUES (?,?,?,?,?,?)',(ek,ck,4,option.source_size,'mapped',1))])
        dbfile(self.queue,common,[])
        dbfile(self.inv,{**common,'source_snapshot_id':sid,'local_storage_snapshot':self.snapshot},[
            ('CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB,archive_id INTEGER,payload_offset INTEGER,encoded_size INTEGER,ckey BLOB,decoded_size INTEGER)',()),
            ('CREATE INDEX candidate_target ON candidates(ekey)',()),
            ('CREATE TABLE archives(archive_id INTEGER PRIMARY KEY,name TEXT,size INTEGER,ambiguous INTEGER)',()),
            ('INSERT INTO archives VALUES (0,?,?,0)',('data.000',5)),
            ('INSERT INTO candidates VALUES (1,?,0,0,4,?,?)',(ek,ck,option.source_size))])
        dbfile(self.ev,{**common,'source_snapshot_id':sid,'local_verification_summary':{'candidate_rows_pending':0,'all_discovered_candidates_processed':True}},[
            ('CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB,kind TEXT,state TEXT,bytes_read INTEGER,decoded_content_verified INTEGER,encoded_object_verified INTEGER,source_path TEXT)',()),
            ('INSERT INTO evidence VALUES (1,?,?,?,?,?,?,?)',(ek,'casc_span','encoded_and_decoded_content_verified',4,1,1,str(self.archive)))])
        self.record={'format':'offline-local-review-1','plan_id':pid,'merged_checkpoint':self.ev.name}
        self.refresh()
    def refresh(self):
        for name,p in [('plan_file',self.plan),('queue_file',self.queue),('local_inventory',self.inv),('latest_local',self.ev)]:
            self.record[name]={'name':p.name,'fingerprint':b.fp(p.stat())}
        self.state={'format':'queue-downloader-ui-1','plan':self.plan.name,'queue':self.queue.name,'local_review':self.record}
        writejson(self.objects/'downloader-ui-session.json',self.state)
    def update(self,path,sql,args=()):
        db=sqlite3.connect(path);db.execute(sql,args);db.commit();db.close();self.refresh()
    def meta(self,path,name,value):self.update(path,'UPDATE metadata SET value=? WHERE name=?',(json.dumps(value),name))
    def run(self,options=None,**kw):
        with patch.object(b,'load_metadata',return_value=(options or [self.option],{'blocks':1},BINDING)):
            return b.bind(self.lab,self.audit,**kw)

class BindingTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.f=Fixture(Path(self.temp.name))
    def tearDown(self):self.temp.cleanup()
    def test_exact_proof_bound_not_authorized(self):
        r,p=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],1)
        self.assertFalse(r['fresh_source_content_verified']);self.assertFalse(p['apply_authorized'])
        self.assertEqual(p['options'][0]['source_ckey'],'77'*16)
    def test_no_payload_opens_no_network_no_input_writes(self):
        paths=list(self.f.lab.rglob('*'))+[self.f.archive]
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
        original=Path.open
        def guarded(p,*args,**kw):
            if p.name=='data.000':raise AssertionError('payload must not open')
            return original(p,*args,**kw)
        with patch.object(Path,'open',guarded),patch('socket.socket',side_effect=AssertionError('no network')):r,_=self.f.run()
        after={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.f.lab.rglob('*') if p.is_file()}
        after[str(self.f.archive)]=hashlib.sha256(self.f.archive.read_bytes()).hexdigest()
        self.assertEqual(before,after);self.assertEqual(r['archive_payload_bytes_read'],0);self.assertEqual(r['network_requests'],0)
    def test_source_outside_prior_target_projection_unknown(self):
        self.f.update(self.f.inv,'DELETE FROM candidates')
        r,_=self.f.run();self.assertEqual(r['options_by_state'],{'source_outside_saved_target_candidate_inventory':1})
        self.assertTrue(r['unknown_is_not_missing_or_corrupt'])
    def test_unverified_candidate_not_proof(self):
        self.f.update(self.f.ev,'UPDATE evidence SET encoded_object_verified=0')
        r,_=self.f.run();self.assertEqual(r['options_by_state'],{'source_candidates_without_full_matching_proof':1})
    def test_decoded_only_not_encoded_proof(self):
        self.f.update(self.f.ev,"UPDATE evidence SET kind='decoded',state='decoded_content_verified',encoded_object_verified=0")
        r,_=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],0)
    def test_short_prefix_not_proof(self):
        self.f.update(self.f.inv,'UPDATE candidates SET ekey=?',(bytes.fromhex(OPT.source_ekey)[:9],))
        r,_=self.f.run();self.assertEqual(r['options_by_state'],{'source_outside_saved_target_candidate_inventory':1})
    def test_wrong_evidence_ekey(self):
        self.f.update(self.f.ev,'UPDATE evidence SET ekey=?',(bytes.fromhex('66'*16),))
        r,_=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],0)
    def test_wrong_ordinal_not_joined_by_key_alone(self):
        self.f.update(self.f.ev,'UPDATE evidence SET ordinal=2')
        r,_=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],0)
    def test_alias_marker_not_proof(self):
        self.f.update(self.f.ev,"UPDATE evidence SET state='already_verified_same_target'")
        r,_=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],0)
    def test_wrong_decoded_size_not_selected(self):
        self.f.update(self.f.inv,'UPDATE candidates SET decoded_size=9')
        r,_=self.f.run();self.assertEqual(r['options_by_state'],{'source_size_conflict_with_saved_candidates':1})
    def test_wrong_read_count_not_proof(self):
        self.f.update(self.f.ev,'UPDATE evidence SET bytes_read=0')
        r,_=self.f.run();self.assertEqual(r['unique_source_ekeys_with_bound_prior_full_proof'],0)
    def test_target_not_in_saved_catalogue(self):
        self.f.update(self.f.plan,'DELETE FROM plan WHERE ckey=?',(bytes.fromhex(OPT.target_ckey),))
        r,_=self.f.run();self.assertEqual(r['options_by_state'],{'target_not_bound_to_saved_catalogue':1})
    def test_source_fingerprint_changed(self):
        self.f.archive.write_bytes(b'changed')
        with self.assertRaises(b.BindingError):self.f.run()
    def test_file_set_changed(self):
        (self.f.game/'extra').write_bytes(b'')
        with self.assertRaisesRegex(b.BindingError,'snapshot_changed'):self.f.run()
    def test_evidence_database_changed(self):
        db=sqlite3.connect(self.f.ev);db.execute('UPDATE evidence SET bytes_read=1');db.commit();db.close()
        with self.assertRaisesRegex(b.BindingError,'fingerprint_changed'):self.f.run()
    def test_source_path_mismatch_refused(self):
        self.f.update(self.f.ev,'UPDATE evidence SET source_path=?',('elsewhere',))
        with self.assertRaisesRegex(b.BindingError,'source_path'):self.f.run()
    def test_bounds_conflict_refused(self):
        self.f.update(self.f.inv,'UPDATE candidates SET payload_offset=3')
        with self.assertRaisesRegex(b.BindingError,'coordinates'):self.f.run()
    def test_ambiguous_archive_refused(self):
        self.f.update(self.f.inv,'UPDATE archives SET ambiguous=1')
        with self.assertRaisesRegex(b.BindingError,'coordinates'):self.f.run()
    def test_cross_plan_refused(self):
        self.f.meta(self.f.ev,'source_plan_id','9'*32)
        with self.assertRaisesRegex(b.BindingError,'plan_id'):self.f.run()
    def test_real_plan_id_contract(self):
        r,private=self.f.run()
        self.assertEqual(private['plan_id'],self.f.plan.stem)
        self.assertTrue(private['plan_id'].startswith('content-plan-'))
    def test_bare_uuid_not_a_saved_plan_identity(self):
        wrong=self.f.plan.stem.removeprefix('content-plan-')
        self.f.meta(self.f.plan,'plan_id',wrong)
        for p in (self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'source_plan_id',wrong)
        self.f.record['plan_id']=wrong;self.f.refresh()
        with self.assertRaisesRegex(b.BindingError,'plan_id_conflict'):self.f.run()
    def test_consistent_id_of_different_plan_file_rejected(self):
        wrong='content-plan-'+'a'*32
        self.f.meta(self.f.plan,'plan_id',wrong)
        for p in (self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'source_plan_id',wrong)
        self.f.record['plan_id']=wrong;self.f.refresh()
        with self.assertRaisesRegex(b.BindingError,'plan_id_conflict'):self.f.run()
    def test_session_id_mismatch_rejected(self):
        self.f.record['plan_id']='content-plan-'+'a'*32;self.f.refresh()
        with self.assertRaisesRegex(b.BindingError,'plan_id_conflict'):self.f.run()
    def test_each_linked_source_plan_id_mismatch_rejected(self):
        for p in (self.f.queue,self.f.inv,self.f.ev):
            with self.subTest(database=p.name):
                self.f.meta(p,'source_plan_id','content-plan-'+'b'*32)
                with self.assertRaisesRegex(b.BindingError,'plan_id_conflict'):self.f.run()
                self.f.meta(p,'source_plan_id',self.f.plan.stem)
    def test_cross_snapshot_refused(self):
        self.f.meta(self.f.ev,'source_snapshot_id','9'*32)
        with self.assertRaisesRegex(b.BindingError,'snapshot_id'):self.f.run()
    def test_target_version_conflict(self):
        binding={**BINDING,'version':'12.1.0.69933'};self.f.meta(self.f.inv,'target_binding',binding)
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_optional_binding_conflict(self):
        self.f.meta(self.f.ev,'target_binding',{**BINDING,'download_ckey':'f'*32})
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_saved_cdn_same_content_accepted_offline(self):
        for p in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'target_binding',{**BINDING,'cdn_config':b.SAVED_CDN})
        r,private=self.f.run()
        self.assertEqual(r['target']['cdn_config'],b.SAVED_CDN)
        self.assertEqual(private['target'],r['target'])
        self.assertEqual(r['audit_metadata_cdn_config'],a.CDN)
        self.assertFalse(r['cdn_routes_used']);self.assertFalse(r['cdn_route_equivalence_claimed'])
        self.assertFalse(r['patch_applied']);self.assertFalse(private['apply_authorized'])
    def test_saved_cdn_mixed_databases_rejected(self):
        self.f.meta(self.f.queue,'target_binding',{**BINDING,'cdn_config':b.SAVED_CDN})
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_unknown_cdn_even_consistent_rejected(self):
        for p in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'target_binding',{**BINDING,'cdn_config':'a'*32})
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_wrong_content_even_consistent_rejected(self):
        for key in ('product','region','version','build_config','download_ckey','download_ekey'):
            with self.subTest(key=key):
                for p in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'target_binding',{**BINDING,'cdn_config':b.SAVED_CDN,key:'0'*32})
                with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_missing_download_even_consistent_rejected(self):
        obj={k:v for k,v in BINDING.items() if k!='download_ekey'}
        for p in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'target_binding',obj)
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_extra_field_disagreement_rejected(self):
        self.f.meta(self.f.ev,'target_binding',{**BINDING,'some_optional_field':'different'})
        with self.assertRaisesRegex(b.BindingError,'target_binding'):self.f.run()
    def test_actual_pinned_download_keys_match_user_report(self):
        root=Path(__file__).resolve().parents[1]/'pinned_metadata'
        _,_,expected=b.load_metadata(root,b.Watch())
        obj={**BINDING,'cdn_config':b.SAVED_CDN}
        self.assertEqual(b.validate_bindings([obj]*4,expected),obj)
    def test_incomplete_review_refused(self):
        self.f.meta(self.f.ev,'local_verification_summary',{'candidate_rows_pending':1,'all_discovered_candidates_processed':False})
        with self.assertRaisesRegex(b.BindingError,'incomplete'):self.f.run()
    def test_dirty_queue_refused(self):
        self.f.record['merged_checkpoint']='different';self.f.refresh()
        with self.assertRaisesRegex(b.BindingError,'unmerged'):self.f.run()
    def test_record_path_traversal_refused(self):
        self.f.record['latest_local']['name']='../e.sqlite';writejson(self.f.objects/'downloader-ui-session.json',self.f.state)
        with self.assertRaisesRegex(b.BindingError,'filename'):self.f.run()
    def test_duplicate_json_keys_refused(self):
        (self.f.objects/'downloader-ui-session.json').write_bytes(b'{"format":1,"format":2}')
        with self.assertRaisesRegex(b.BindingError,'duplicate'):self.f.run()
    def test_public_report_has_no_paths(self):
        r,_=self.f.run();text=json.dumps(r)
        self.assertNotIn(str(self.f.root),text);self.assertNotIn('data.000',text);self.assertNotIn('source_path',text)
    def test_private_plan_limit(self):
        r,p=self.f.run(options=[OPT]*3,max_private=1)
        self.assertEqual(r['bounded_options_for_future_targeted_reverification'],3);self.assertEqual(len(p['options']),1)
    def test_zero_based_and_other_ordinals_not_guessed(self):
        other=a.PatchOption(*list(asdict_values(OPT))[:-1],4)
        r,p=self.f.run(options=[OPT,other]);self.assertFalse(r['patch_order_policy_proven'])
        self.assertEqual({o['ordinal'] for o in p['options']},{0,4})
    def test_cancel_refused(self):
        with self.assertRaises(b.BindingError):self.f.run(cancel=lambda:True)
    def test_timeout_refused(self):
        with self.assertRaises(b.BindingError):self.f.run(time_limit=0)
    def test_source_index_required_no_repeated_scan_fallback(self):
        self.f.update(self.f.inv,'DROP INDEX candidate_target')
        with self.assertRaisesRegex(b.BindingError,'ekey_index'):self.f.run()
    def test_sidecar_refused(self):
        Path(str(self.f.ev)+'-wal').write_bytes(b'x')
        with self.assertRaisesRegex(b.BindingError,'sidecar'):self.f.run()
    def test_symlink_archive_refused(self):
        old=self.f.archive;new=self.f.root/'actual';old.rename(new);old.symlink_to(new)
        self.f.snapshot['directory_identity']=b.fp(self.f.game.stat());self.f.snapshot['files']['data.000']=b.fp(old.stat())
        self.f.meta(self.f.inv,'local_storage_snapshot',self.f.snapshot)
        with self.assertRaisesRegex(b.BindingError,'link_or_reparse'):self.f.run()

def asdict_values(o):
    from dataclasses import asdict
    return asdict(o).values()


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.f=Fixture(Path(self.tmp.name))
        self.public,self.private=self.f.run()
    def tearDown(self):self.tmp.cleanup()
    def test_publish_outside_lab(self):
        import source_check as c
        dest=self.f.root/'output';out=c.publish(self.f.lab,self.public,self.private,dest)
        self.assertTrue((out/'Retail-Patch-Source-Binding-to-share.json').is_file())
        public=(out/'Retail-Patch-Source-Binding-to-share.json').read_text()
        self.assertNotIn(str(self.f.game),public)
    def test_no_publish_inside_lab(self):
        import source_check as c
        with self.assertRaisesRegex(b.BindingError,'outside_sources'):c.publish(self.f.lab,self.public,self.private,self.f.lab/'results')
        self.assertFalse((self.f.lab/'results').exists())
    def test_no_publish_inside_source(self):
        import source_check as c
        with self.assertRaisesRegex(b.BindingError,'outside_sources'):c.publish(self.f.lab,self.public,self.private,self.f.game/'results')
        self.assertFalse((self.f.game/'results').exists())
    def test_no_existing_output_overwrite(self):
        import source_check as c
        p=self.f.root/'output';p.mkdir();(p/'important').write_bytes(b'preserve')
        with self.assertRaisesRegex(b.BindingError,'new_output'):c.publish(self.f.lab,self.public,self.private,p)
        self.assertEqual((p/'important').read_bytes(),b'preserve')
    def test_symlink_parent_rejected(self):
        import source_check as c
        p=self.f.root/'link';p.symlink_to(self.f.game,target_is_directory=True)
        with self.assertRaises(b.BindingError):c.publish(self.f.lab,self.public,self.private,p/'output')


class BundledMetadataTests(unittest.TestCase):
    def test_full_real_bundled_manifest(self):
        options,report,binding=b.load_metadata(Path(__file__).resolve().parents[1]/'pinned_metadata',b.Watch())
        self.assertEqual(len(options),27994);self.assertEqual(report['blocks'],28);self.assertEqual(binding,BINDING)
    def test_modified_base64_shard_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'metadata'
            shutil.copytree(Path(__file__).resolve().parents[1]/'pinned_metadata',dest)
            p=dest/'manifest.pa.base64.part0';data=p.read_bytes();p.write_bytes(b'!'+data[1:])
            with self.assertRaisesRegex(b.BindingError,'manifest_encoding'):b.load_metadata(dest,b.Watch())

if __name__=='__main__':unittest.main()
