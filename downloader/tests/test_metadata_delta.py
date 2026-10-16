import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import installed_metadata as im
import metadata_delta as delta
import local_casc as local
import plan_storage as store
import repair_core as core
import test_download_inventory as di
import test_local_casc as lt
import test_repair_core as rt


def md5(b):return hashlib.md5(b).hexdigest()

def info(key,version='12.1.5.70390',product='wow',tags='Windows x86_64 EU enUS speech:Windows x86_64 EU enUS text'):
    return ('Product!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Version!STRING:0|Branch!STRING:0|Tags!STRING:0|Keyring!HEX:16\n'
            +product+'|1|'+key+'|'+'b'*32+'|'+version+'|eu|'+tags+'|DO-NOT-EXPOSE-PRIVATE-FIELD\n').encode()


class BuildInfoTests(unittest.TestCase):
    def test_select_active_retail_not_classic(self):
        raw=info('a'*32)+info('b'*32,product='wow_classic').split(b'\n',1)[1]
        self.assertEqual(im.select_row(raw)['buildkey'],'a'*32)
    def test_active_row_is_not_proof_of_payload_health(self):
        row=im.select_row(info('a'*32));self.assertNotIn('keyring',row)
    def test_missing_product_allowed_only_single_active_row(self):
        r=b'Active|Build Key|Version\n1|'+b'a'*32+b'|12.1.5.70390\n'
        self.assertEqual(im.select_row(r)['product'],'')
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):im.select_row(r+r.split(b'\n',1)[1])
    def test_duplicate_header_normalized_spaces(self):
        with self.assertRaisesRegex(core.RepairError,'duplicate_header'):im.select_row(b'Active|Build Key|BuildKey\n1|a|b\n')
    def test_invalid_build_key_path_refused(self):
        with self.assertRaises(core.RepairError):im.select_row(info('../../secret'))
    def test_invalid_version_refused(self):
        with self.assertRaises(core.RepairError):im.select_row(info('a'*32,version='secret/path'))
    def test_wrong_product_no_silent_retail_fallback(self):
        with self.assertRaisesRegex(core.RepairError,'missing_or_ambiguous'):im.select_row(info('a'*32,product='wow_classic'))
    def test_two_active_retail_rows_ambiguous(self):
        raw=info('a'*32)+info('b'*32).split(b'\n',1)[1]
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):im.select_row(raw)
    def test_non_utf8_refused(self):
        with self.assertRaisesRegex(core.RepairError,'encoding'):im.select_row(b'\xff\xfeinvalid')
    def test_row_width_refused(self):
        with self.assertRaisesRegex(core.RepairError,'row_width'):im.select_row(b'Active|Build Key\n1|a|extra\n')
    def test_descriptor_missing_full_pair_does_not_guess_ekey(self):
        with self.assertRaisesRegex(core.RepairError,'full_key_pair'):im.download_descriptor({'download':['a'*32],'download-size':['1','2']})
    def test_descriptor_caps_metadata_size(self):
        with self.assertRaisesRegex(core.RepairError,'size_limit'):im.download_descriptor({'download':['a'*32,'b'*32],'download-size':[str(257*1024**2),'2']})


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve()
        self.lab=core.Lab.create(self.base/'lab');self.game=self.base/'game';self.storage=self.game/'Data'/'data';self.storage.mkdir(parents=True)
        self.old_data=di.fixture([(b'a'*16,100,0),(b'b'*16,200,1),(b'a'*16,100,0)])
        self.target_data=di.fixture([(b'b'*16,200,1),(b'c'*16,300,0)])
        self.old_blob,self.old_ek=rt.encoded(self.old_data,table=True);self.old_ck=md5(self.old_data)
        self.target_ck=md5(self.target_data)
        self.build=('build-uid = wow\nbuild-name = WOW-70390patch12.1.5_Retail\ndownload = %s %s\ndownload-size = %d %d\n'%(self.old_ck,self.old_ek,len(self.old_data),len(self.old_blob))).encode()
        self.bk=md5(self.build);self.config=self.game/'Data'/'config'/self.bk[:2]/self.bk[2:4]/self.bk;self.config.parent.mkdir(parents=True);self.config.write_bytes(self.build)
        (self.game/'.build.info').write_bytes(info(self.bk))
        self.offset=256;raw=bytearray(4096);raw[self.offset:self.offset+30+len(self.old_blob)]=bytes(30)+self.old_blob
        self.archive=self.storage/'data.000';self.archive.write_bytes(raw)
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));self.index=self.storage/('%02x00000001.idx'%bucket);self.index.write_bytes(lt.idx([lt.entry(bytes.fromhex(self.old_ek),offset=self.offset,size=len(self.old_blob)+30)],group=bucket))
        self.target_cache=self.lab.root/'objects'/(self.target_ck+'-'+str(len(self.target_data))+'.decoded');self.target_cache.write_bytes(self.target_data)
        self.binding=dict(product='wow',region='eu',version='12.1.5.70391',build_config='c'*32,cdn_config='d'*32,download_ckey=self.target_ck,download_ekey='e'*32)
        with store.Writer(self.lab,'content-plan',threading.Event()) as out:
            out.db.execute('CREATE TABLE plan(ekey BLOB PRIMARY KEY,encoded_size INTEGER,ckey BLOB,decoded_size INTEGER,mapping_state TEXT,transfer_supported INTEGER,route_kind TEXT)');out.db.executemany('INSERT INTO plan VALUES (?,?,?,?,?,?,?)',[(b'b'*16,200,b'B'*16,999,'mapped',1,'archive_range'),(b'c'*16,300,b'C'*16,999,'mapped',1,'archive_range')]);out.metadata('target_binding',self.binding);out.metadata('plan_id',out.path.stem)
        self.plan=out.path
        self.state=self.lab.root/'objects'/'downloader-ui-session.json';core.atomic_json(self.state,{'KEEP':'existing review pointer'})
        self.net=patch.object(core.HTTPS,'open',side_effect=AssertionError('network forbidden'));self.net.start();self.addCleanup(self.net.stop)
    def runplan(self,**kw):return delta.plan(self.lab,self.plan,self.storage,**kw)
    def source_hashes(self):return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.game.rglob('*') if p.is_file()}
    def cache_old(self):
        p=self.lab.root/'objects'/(self.old_ck+'-'+str(len(self.old_data))+'.decoded');p.write_bytes(self.old_data);return p
    def test_installed_identity_verified_and_public_whitelist(self):
        identity=im.read(self.game);r=identity.public();self.assertEqual(r['version'],'12.1.5.70390');self.assertIn('enUS',r['known_tag_tokens']);self.assertNotIn('PRIVATE',json.dumps(r));self.assertFalse(r['installed_files_health_proven'])
    def test_config_md5_mismatch_refused(self):
        self.config.write_bytes(self.build+b'# changed')
        with self.assertRaisesRegex(core.RepairError,'config_checksum'):im.read(self.game)
    def test_version_row_config_disagreement_refused(self):
        (self.game/'.build.info').write_bytes(info(self.bk,version='12.1.5.70389'))
        with self.assertRaisesRegex(core.RepairError,'version_config_conflict'):im.read(self.game)
    def test_config_product_not_wow_refused(self):
        raw=self.build.replace(b'build-uid = wow',b'build-uid = wow_classic');bk=md5(raw);p=self.game/'Data'/'config'/bk[:2]/bk[2:4]/bk;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);(self.game/'.build.info').write_bytes(info(bk))
        with self.assertRaisesRegex(core.RepairError,'not_retail'):im.read(self.game)
    def test_full_offline_archive_metadata_delta_no_sources_changed(self):
        before=self.source_hashes();state=self.state.read_bytes();plan=self.plan.read_bytes();target=self.target_cache.read_bytes()
        r=self.runplan();d=r['logical_catalogue_delta']
        self.assertEqual((d['old_catalogue_objects'],d['target_catalogue_objects'],d['common_encoded_keys'],d['added_encoded_keys'],d['removed_encoded_keys']),(2,2,1,1,1));self.assertEqual(d['added_full_encoded_representation_bytes'],300)
        self.assertTrue(d['independent_set_reconciliation_passed']);self.assertEqual(r['old_manifest_metadata']['archive_metadata_bytes_read'],len(self.old_blob))
        self.assertFalse(r['full_asset_verification_performed']);self.assertEqual(r['network_requests'],0);self.assertFalse(r['Agent_started']);self.assertFalse(r['pinned_target_is_latest_online_proven']);self.assertIsNone(r['required_network_download_bytes'])
        self.assertEqual(self.source_hashes(),before);self.assertEqual(self.state.read_bytes(),state);self.assertEqual(self.plan.read_bytes(),plan);self.assertEqual(self.target_cache.read_bytes(),target)
    def test_cached_old_manifest_does_not_open_game_archives_or_indexes(self):
        self.cache_old();original=io.open
        def opened(path,*a,**kw):
            if isinstance(path,(str,Path)) and Path(path).parent==self.storage:raise AssertionError('archive or index read despite cached metadata')
            return original(path,*a,**kw)
        with patch('io.open',side_effect=opened):r=self.runplan()
        self.assertEqual(r['old_manifest_metadata']['archive_metadata_bytes_read'],0)
    def test_archive_reads_only_exact_download_metadata_slice(self):
        original=io.open;reads=[];start=self.offset+30;end=start+len(self.old_blob)
        def opened(path,*a,**kw):
            f=original(path,*a,**kw)
            if not isinstance(path,(str,Path)) or Path(path)!=self.archive:return f
            class File:
                def __getattr__(self,k):return getattr(f,k)
                def __enter__(self):return self
                def __exit__(self,*args):return f.__exit__(*args)
                def read(self,n=-1):
                    selfpos=f.tell()
                    if n<0 or not start<=selfpos<=end or selfpos+n>end:raise AssertionError('non-metadata archive payload read')
                    b=f.read(n);reads.append(len(b));return b
            return File()
        with patch('io.open',side_effect=opened):self.runplan()
        self.assertEqual(sum(reads),len(self.old_blob))
    def test_missing_old_manifest_no_network_fallback(self):
        self.index.unlink()
        with self.assertRaisesRegex(core.RepairError,'not_found_locally'):self.runplan()
    def test_bad_index_checksum_not_trusted(self):
        raw=bytearray(self.index.read_bytes());raw[-1]^=1;self.index.write_bytes(raw)
        with self.assertRaisesRegex(core.RepairError,'not_found_locally'):self.runplan()
    def test_bad_old_metadata_chunk_not_accepted_as_healthy(self):
        raw=bytearray(self.archive.read_bytes());raw[self.offset+30+len(self.old_blob)-1]^=1;self.archive.write_bytes(raw)
        with self.assertRaisesRegex(core.RepairError,'not_fully_proven'):self.runplan()
    def test_corrupt_cached_target_fails_before_workspace(self):
        self.target_cache.write_bytes(bytes(len(self.target_data)))
        with self.assertRaisesRegex(core.RepairError,'ckey_mismatch'):self.runplan()
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')))
    def test_missing_cached_target_no_network(self):
        self.target_cache.unlink()
        with self.assertRaisesRegex(core.RepairError,'missing_from_cache_no_network'):self.runplan()
    def test_ambiguous_cached_target_refused(self):
        p=self.target_cache.with_name(self.target_ck+'-other.decoded');p.write_bytes(self.target_data)
        with self.assertRaisesRegex(core.RepairError,'ambiguous'):self.runplan()
    def test_changed_build_info_during_parse_prevents_publication(self):
        self.cache_old();changed=[]
        def progress(e):
            if not changed:(self.game/'.build.info').write_bytes(info(self.bk)+b'\n');changed.append(True)
        with self.assertRaisesRegex(core.RepairError,'installed_metadata_changed'):self.runplan(notify=progress)
        self.assertFalse(list((self.lab.root/'objects').glob('Retail-Metadata-Plan-to-share-*.json')))
    def test_pre_cancel_no_planning_workspace(self):
        cancel=threading.Event();cancel.set()
        with self.assertRaises(core.Cancelled):self.runplan(cancel=cancel)
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')))
    def test_metadata_archive_read_budget_checked_before_payload(self):
        with patch.object(delta,'MAX_ARCHIVE_META_READ',1):
            with self.assertRaisesRegex(core.RepairError,'read_budget'):self.runplan()
    def test_low_free_space_does_not_start_new_workspace(self):
        with patch.object(delta.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
            with self.assertRaisesRegex(core.RepairError,'space_preflight'):self.runplan()
        self.assertFalse(list(self.lab.root.glob('metadata-planning-*')))
    def test_shared_ekey_different_size_refused_not_counted_as_download(self):
        changed=di.fixture([(b'b'*16,201,0),(b'c'*16,300,1)]);self.target_cache.unlink();ck=md5(changed);self.target_cache=self.lab.root/'objects'/(ck+'-'+str(len(changed))+'.decoded');self.target_cache.write_bytes(changed)
        db=sqlite3.connect(self.plan)
        try:
            binding=dict(self.binding,download_ckey=ck);db.execute("UPDATE metadata SET value=? WHERE name='target_binding'",(json.dumps(binding),));db.commit()
        finally:db.close()
        with self.assertRaisesRegex(core.RepairError,'shared_ekey_size_conflict'):self.runplan()
    def test_public_report_has_no_paths_keyring_or_unknown_tags(self):
        (self.game/'.build.info').write_bytes(info(self.bk,tags='Windows enUS SECRET_ACCOUNT_MARKER'))
        r=self.runplan();text=json.dumps(r);self.assertNotIn(str(self.base),text);self.assertNotIn('SECRET',text);self.assertNotIn('DO-NOT-EXPOSE',text)
        for path in (self.lab.root/'objects').glob('Retail-Metadata-Plan-to-share-*.json'):self.assertNotIn(str(self.base),path.read_text())
    def test_lab_inside_game_refused(self):
        bad=core.Lab.create(self.game/'bad-lab')
        with self.assertRaisesRegex(core.RepairError,'workspace_inside_game_root'):delta.plan(bad,self.plan,self.storage)
    def test_build_info_symlink_refused(self):
        p=self.game/'.build.info';other=self.base/'other';os.replace(p,other);p.symlink_to(other)
        with self.assertRaisesRegex(core.RepairError,'link_or_reparse'):self.runplan()
    def test_no_config_path_search_or_network_if_missing_exact_config(self):
        self.config.unlink()
        with self.assertRaises(FileNotFoundError):self.runplan()
    def test_lookup_reads_only_known_prefix_bucket_not_all_journals(self):
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));other=(bucket+1)%16
        p=self.storage/('%02x00000001.idx'%other);p.write_bytes(b'not relevant to this key')
        original=local._read_index;seen=[]
        def read(path,*a,**kw):seen.append(path);return original(path,*a,**kw)
        with patch.object(local,'_read_index',side_effect=read):self.runplan()
        self.assertEqual(seen,[self.index])
    def test_bucket_matches_independent_nibble_xor(self):
        for i in range(64):
            key=hashlib.sha256(str(i).encode()).digest()[:16];value=0
            for c in key[:9].hex():value^=int(c,16)
            self.assertEqual(delta.index_bucket(key),value)
    def test_source_direct_reference_without_wrapper_supported(self):
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));self.index.write_bytes(lt.idx([lt.entry(bytes.fromhex(self.old_ek),offset=self.offset+30,size=len(self.old_blob))],group=bucket))
        self.assertEqual(self.runplan()['old_manifest_metadata']['archive_metadata_bytes_read'],len(self.old_blob))
    def test_duplicate_wrapper_direct_alias_decodes_once(self):
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));self.index.write_bytes(lt.idx([lt.entry(bytes.fromhex(self.old_ek),offset=self.offset,size=len(self.old_blob)+30),lt.entry(bytes.fromhex(self.old_ek),offset=self.offset+30,size=len(self.old_blob))],group=bucket))
        r=self.runplan();self.assertEqual(r['old_manifest_metadata']['candidate_metadata_locations'],1);self.assertEqual(r['old_manifest_metadata']['archive_metadata_bytes_read'],len(self.old_blob))
    def test_normal_manifest_v1_supported(self):
        workspace=core.Lab.create(self.base/'test-manifest-v1');raw=di.fixture([(b'a'*16,13,0)],version=1);p=workspace.root/'objects'/'source.decoded';p.write_bytes(raw)
        path=delta.inventory(workspace,p,md5(raw),self.binding)
        with store.input_db(workspace,path) as (db,_):self.assertEqual(db.execute('SELECT COUNT(*) FROM objects').fetchone()[0],1)
    def test_full_queue_anchor_entrypoint_keeps_review_pointer(self):
        import reuse_coordinator as reuse
        _,inv=local.inventory(self.lab,self.plan,self.storage);_,ev=local.verify_batch(self.lab,self.plan,inv)
        _,ri=reuse.inventory(self.lab,self.plan,local_inputs=[(inv,ev)]);_,re=reuse.verify_batch(self.lab,self.plan,ri);_,q=reuse.make_queue(self.lab,self.plan,ri,re)
        before=self.state.read_bytes();r=delta.plan_from_queue(self.lab,self.plan,q)
        self.assertEqual(r['status'],'logical_catalogue_delta_complete');self.assertEqual(self.state.read_bytes(),before)
    def test_bad_first_candidate_valid_second_candidate_not_a_corruption_verdict(self):
        raw=bytearray(self.archive.read_bytes());bad=bytearray(self.old_blob);bad[-1]^=1;raw[128:128+30+len(bad)]=bytes(30)+bad;self.archive.write_bytes(raw)
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));self.index.write_bytes(lt.idx([lt.entry(bytes.fromhex(self.old_ek),offset=128,size=len(bad)+30),lt.entry(bytes.fromhex(self.old_ek),offset=self.offset,size=len(self.old_blob)+30)],group=bucket))
        r=self.runplan();self.assertEqual(r['old_manifest_metadata']['candidate_metadata_locations'],2);self.assertEqual(r['old_manifest_metadata']['archive_metadata_bytes_read'],2*len(self.old_blob))
    def test_too_many_matching_prefix_locations_refused(self):
        bucket=delta.index_bucket(bytes.fromhex(self.old_ek));self.index.write_bytes(lt.idx([lt.entry(bytes.fromhex(self.old_ek),offset=i*40,size=len(self.old_blob)+30) for i in range(65)],group=bucket))
        with self.assertRaisesRegex(core.RepairError,'candidate_limit'):self.runplan()
    def test_cancel_during_index_lookup_no_report(self):
        event=threading.Event()
        def progress(e):
            if e['stage']=='old_download_index_lookup':event.set()
        with self.assertRaises(core.Cancelled):self.runplan(cancel=event,notify=progress)
        self.assertFalse(list((self.lab.root/'objects').glob('Retail-Metadata-Plan-to-share-*.json')))
    def test_cached_manifest_symlink_refused(self):
        original=self.base/'cache-copy';os.replace(self.target_cache,original);self.target_cache.symlink_to(original)
        with self.assertRaisesRegex(core.RepairError,'link_or_reparse'):self.runplan()
    def test_same_manifest_zero_delta_does_not_claim_no_download_needed(self):
        self.target_cache.unlink();self.target_cache=self.lab.root/'objects'/(self.old_ck+'-'+str(len(self.old_data))+'.decoded');self.target_cache.write_bytes(self.old_data)
        db=sqlite3.connect(self.plan)
        try:db.execute("UPDATE metadata SET value=? WHERE name='target_binding'",(json.dumps(dict(self.binding,download_ckey=self.old_ck)),));db.commit()
        finally:db.close()
        r=self.runplan();self.assertEqual(r['logical_catalogue_delta']['added_encoded_keys'],0);self.assertIsNone(r['required_network_download_bytes']);self.assertFalse(r['installed_identity']['installed_files_health_proven'])

if __name__=='__main__':unittest.main()
