import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_casc as lc
import lookup3 as h
import repair_core as core
import plan_storage as store
import test_repair_core as rt


def entry(key, aid=0, offset=0, size=30):
    return key[:9]+((aid<<30)|offset).to_bytes(5,'big')+size.to_bytes(4,'little')


def idx(entries, group=0, variant='native', trailing=b''):
    header=struct.pack('<HBBBBBBQ',7,group,0,4,5,9,30,0x4000000000)
    hi=lo=0
    for e in entries:
        if variant=='native': hi,lo=h.hashlittle2(e,hi,lo)
        else: hi=h.hashlittle(e,hi)
    body=b''.join(entries)
    return struct.pack('<II',16,h.hashlittle(header))+header+bytes(8)+struct.pack('<II',len(body),hi)+body+trailing


class IndexProofTests(unittest.TestCase):
    def proof(self, raw=None, name='0000000001.idx'):
        return lc.index_proof(raw if raw is not None else idx([entry(bytes(16))]),name,threading.Event())

    def test_native(self): self.assertTrue(self.proof()['checksum_verified'])
    def test_blizzget(self):
        self.assertEqual(self.proof(idx([entry(bytes(16)),entry(b'a'*16)],variant='blizzget'))['checksum_variant'],'blizzget_rolling_hashlittle')
    def test_bad_header(self):
        b=bytearray(idx([entry(bytes(16))]));b[20]^=1
        self.assertEqual(self.proof(b)['state'],'header_checksum_not_verified')
    def test_bad_entry(self):
        b=bytearray(idx([entry(bytes(16))]));b[-1]^=1
        self.assertEqual(self.proof(b)['state'],'entry_checksum_not_verified')
    def test_truncated(self): self.assertFalse(self.proof(idx([entry(bytes(16))])[:-1])['checksum_verified'])
    def test_empty_unknown(self): self.assertFalse(self.proof(idx([]))['checksum_verified'])
    def test_wrong_generation_name(self): self.assertFalse(self.proof(name='unknown.idx')['checksum_verified'])
    def test_wrong_bucket(self): self.assertFalse(self.proof(name='0100000001.idx')['checksum_verified'])
    def test_non_30_segment_bits_unknown(self):
        b=bytearray(idx([entry(bytes(16))]));b[15]=29
        self.assertFalse(self.proof(b)['checksum_verified'])
    def test_trailing_not_trusted(self): self.assertEqual(self.proof(idx([entry(bytes(16))],trailing=b'abc'))['trailing_bytes_not_interpreted'],3)
    def test_cancel(self):
        c=threading.Event();c.set()
        with self.assertRaises(core.Cancelled):lc.index_proof(idx([entry(bytes(16))]),'0000000001.idx',c)
    def test_c_reference_vectors(self):
        vectors=json.loads((Path(__file__).parent/'lookup3-c-reference-vectors.json').read_text())
        for v in vectors['vectors']: self.assertEqual(h.hashlittle2(bytes.fromhex(v['hex']),v['pc'],v['pb']),tuple(v['result']))
        for v in vectors['rolling18']:
            raw=bytes.fromhex(v['hex']);header=struct.pack('<HBBBBBBQ',7,0,0,4,5,9,30,0x4000000000)
            for value in (v['native'][0],v['blizzget']):
                b=struct.pack('<II',16,h.hashlittle(header))+header+bytes(8)+struct.pack('<II',len(raw),value)+raw
                self.assertTrue(self.proof(b)['checksum_verified'])


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.lab=core.Lab.create(self.base/'lab')
        self.folder=self.base/'game'/'Data'/'data';self.folder.mkdir(parents=True)
        self.data=[b'First target payload'*23,b'Second target payload'*13,b'Third target payload'*17]
        encoded=[rt.encoded(d,table=i==1) for i,d in enumerate(self.data)]
        self.blobs=[r[0] for r in encoded];self.keys=[bytes.fromhex(r[1]) for r in encoded]
        self.cks=[hashlib.md5(d).digest() for d in self.data]
        self.binding=dict(product='wow',region='eu',version='test',build_config='a'*32,cdn_config='b'*32)
        self.plan=self.make_plan()
        self.offsets=[500,1500,2500]
        raw=bytearray(4000)
        self.entries=[]
        for i,b in enumerate(self.blobs):
            off=self.offsets[i];raw[off:off+len(b)+30]=bytes(30)+b
            self.entries.extend([entry(self.keys[i],offset=off,size=len(b)+30),entry(self.keys[i],offset=off+30,size=len(b))])
        (self.folder/'data.000').write_bytes(raw)
        self.index_path=self.folder/'0000000001.idx'
        self.index_path.write_bytes(idx(self.entries))

    def make_plan(self, keys=None):
        keys=self.keys if keys is None else keys
        with store.Writer(self.lab,'fixture-plan',threading.Event()) as out:
            out.db.execute('''CREATE TABLE plan(ekey BLOB PRIMARY KEY,encoded_size INTEGER,
                ckey BLOB,decoded_size INTEGER,mapping_state TEXT,route_kind TEXT,transfer_supported INTEGER)''')
            for i,key in enumerate(keys):
                out.db.execute('INSERT INTO plan VALUES (?,?,?,?,?,?,?)',(key,len(self.blobs[i]),self.cks[i],len(self.data[i]),'mapped','archive',1))
            out.metadata('target_binding',self.binding)
            out.metadata('plan_id',os.urandom(16).hex())
        return out.path

    def inv(self, **kw): return lc.inventory(self.lab,self.plan,self.folder,**kw)
    def verify(self, inv, **kw): return lc.verify_batch(self.lab,self.plan,inv,**kw)
    def db(self, p):
        db=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True);self.addCleanup(db.close);return db
    def source_hashes(self):
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.folder.iterdir() if p.is_file()}
    def sql_change(self, query, args=()):
        db=sqlite3.connect(self.plan)
        try:
            db.execute(query,args);db.commit()
        finally:
            db.close()

    def test_full_chain_alias_dedup_and_reuse(self):
        before=self.source_hashes();r,inv=self.inv();v,ev=self.verify(inv);s=lc.remaining(self.lab,self.plan,inv,ev)
        self.assertEqual((r['normalized_candidates'],r['reference_aliases_collapsed']),(3,3))
        self.assertEqual(v['target_objects_fully_verified_locally'],3)
        self.assertEqual(s['remaining_conditional_transfer_candidates'],0)
        self.assertIsNone(s['required_network_download_bytes'])
        self.assertFalse(s['installation_ready']);self.assertEqual(self.source_hashes(),before)
    def test_inventory_never_reads_archive_or_shmem(self):
        (self.folder/'shmem').write_bytes(b'do not read')
        original=io.open
        def guard(path,*args,**kw):
            if isinstance(path,(str,Path)) and Path(path).name in ('data.000','shmem'): raise AssertionError('payload opened')
            return original(path,*args,**kw)
        with patch('io.open',side_effect=guard):r,_=self.inv()
        self.assertEqual(r['archive_payload_bytes_read'],0)
    def test_zero_wrapper_allowed_only_with_full_proof(self):
        _,inv=self.inv();r,_=self.verify(inv);self.assertEqual(r['target_objects_fully_verified_locally'],3)
    def test_bad_payload_not_reusable(self):
        p=self.folder/'data.000';raw=bytearray(p.read_bytes());raw[self.offsets[0]+40]^=3;p.write_bytes(raw)
        _,inv=self.inv();r,ev=self.verify(inv);s=lc.remaining(self.lab,self.plan,inv,ev)
        self.assertEqual(r['target_objects_fully_verified_locally'],2)
        self.assertEqual(s['remaining_conditional_transfer_candidates'],1)
        self.assertIn('candidate_content_mismatch',r['evidence_state_counts'])
    def test_chunk_checksum_not_just_ekey_header(self):
        p=self.folder/'data.000';raw=bytearray(p.read_bytes());raw[self.offsets[1]+30+len(self.blobs[1])-1]^=1;p.write_bytes(raw)
        _,inv=self.inv();r,_=self.verify(inv);self.assertEqual(r['target_objects_fully_verified_locally'],2)
    def test_prefix_collision_never_counts_as_possession(self):
        keys=list(self.keys);keys[0]=keys[0][:9]+b'collide';self.plan=self.make_plan(keys)
        _,inv=self.inv();r,_=self.verify(inv);self.assertEqual(r['target_objects_fully_verified_locally'],2)
    def test_wrong_ckey_not_reusable(self):
        self.sql_change('UPDATE plan SET ckey=? WHERE ekey=?',(b'x'*16,self.keys[0]))
        _,inv=self.inv();r,_=self.verify(inv);self.assertEqual(r['target_objects_fully_verified_locally'],2)
    def test_missing_archive_is_unknown(self):
        (self.folder/'data.000').unlink();r,inv=self.inv();v,ev=self.verify(inv)
        self.assertEqual(r['normalized_candidates'],0);self.assertEqual(r['references_without_unambiguous_in_bounds_archive'],6)
        self.assertEqual(lc.remaining(self.lab,self.plan,inv,ev)['remaining_conditional_transfer_candidates'],3)
    def test_ambiguous_archive_id_not_chosen(self):
        (self.folder/'data.0000').write_bytes((self.folder/'data.000').read_bytes())
        r,_=self.inv();self.assertEqual(r['ambiguous_archive_ids'],1);self.assertEqual(r['normalized_candidates'],0)
    def test_out_of_bounds_never_candidate(self):
        self.index_path.write_bytes(idx([entry(self.keys[0],offset=3999,size=len(self.blobs[0]))]))
        r,_=self.inv();self.assertEqual(r['normalized_candidates'],0)
    def test_wrong_span_not_normalized_by_magic_guess(self):
        self.index_path.write_bytes(idx([entry(self.keys[0],offset=530,size=len(self.blobs[0])+1)]))
        r,_=self.inv();self.assertEqual(r['normalized_candidates'],0)
    def test_multiple_generations_no_newest_selection(self):
        (self.folder/'0000000002.idx').write_bytes(idx([entry(self.keys[0],offset=3500,size=len(self.blobs[0]))]))
        r,inv=self.inv();v,_=self.verify(inv)
        self.assertEqual(r['buckets_with_multiple_observed_generations'],1)
        self.assertFalse(r['active_generation_resolved']);self.assertEqual(v['target_objects_fully_verified_locally'],3)
    def test_alternative_after_bad_reference_checked(self):
        self.index_path.write_bytes(idx([entry(self.keys[0],offset=0,size=len(self.blobs[0])),self.entries[0]]))
        _,inv=self.inv();v,_=self.verify(inv)
        self.assertEqual(v['target_objects_fully_verified_locally'],1)
        self.assertEqual(v['batch_candidate_rows_completed'],2)
    def test_success_skips_other_physical_candidate(self):
        self.index_path.write_bytes(idx([self.entries[0],entry(self.keys[0],offset=3500,size=len(self.blobs[0]))]))
        _,inv=self.inv();v,_=self.verify(inv)
        self.assertEqual(v['batch_archive_bytes_read'],len(self.blobs[0]));self.assertEqual(v['evidence_state_counts']['already_verified_same_target'],1)
    def test_unknown_index_not_parsed_as_references(self):
        (self.folder/'unknown.idx').write_bytes(b'unknown');r,_=self.inv()
        self.assertFalse(r['all_observed_index_blocks_verified']);self.assertEqual(r['normalized_candidates'],3)
    def test_corrupt_checksum_never_exposes_candidates(self):
        b=bytearray(self.index_path.read_bytes());b[-1]^=1;self.index_path.write_bytes(b)
        r,_=self.inv();self.assertFalse(r['all_observed_index_blocks_verified']);self.assertEqual(r['normalized_candidates'],0)
    def test_nonzero_bucket_supported(self):
        self.index_path.rename(self.folder/'0f00000001.idx');(self.folder/'0f00000001.idx').write_bytes(idx(self.entries,group=15))
        r,_=self.inv();self.assertEqual(r['normalized_candidates'],3)
    def test_unsupported_plan_entry_not_verifiable(self):
        self.sql_change('UPDATE plan SET transfer_supported=0 WHERE ekey=?',(self.keys[0],))
        r,_=self.inv();self.assertEqual(r['normalized_candidates'],2)
    def test_zero_budget_preserves_all_pending(self):
        _,inv=self.inv();r,ev=self.verify(inv,byte_budget=0)
        self.assertEqual(r['candidate_rows_pending'],3);self.assertEqual(r['batch_archive_bytes_read'],0)
        self.assertEqual(r['stop_reason'],'byte_budget_next_candidate_pending')
        r2,_=self.verify(inv,previous=ev);self.assertEqual(r2['target_objects_fully_verified_locally'],3)
    def test_budget_and_batch_resume_no_rehash_completed(self):
        _,inv=self.inv();r,ev=self.verify(inv,max_candidates=1)
        self.assertEqual(r['candidate_rows_completed'],1)
        original=lc.cache._verify
        def check(*args):
            self.assertNotEqual(args[4],self.db(ev).execute('SELECT ekey FROM evidence').fetchone()[0]);return original(*args)
        with patch.object(lc.cache,'_verify',side_effect=check):r2,ev2=self.verify(inv,previous=ev)
        self.assertEqual(r2['target_objects_fully_verified_locally'],3)
        self.assertEqual(r2['batch_candidate_rows_completed'],2)
        self.assertEqual(self.db(ev).execute('SELECT COUNT(*) FROM evidence').fetchone()[0],1)
    def test_completed_resume_does_no_payload_reads(self):
        _,inv=self.inv();r,ev=self.verify(inv)
        with patch.object(lc.cache,'_verify',side_effect=AssertionError('rehash')):r2,_=self.verify(inv,previous=ev)
        self.assertEqual(r2['batch_archive_bytes_read'],0)
    def test_changed_archive_blocks_resume_and_summary(self):
        _,inv=self.inv();_,ev=self.verify(inv,max_candidates=1)
        p=self.folder/'data.000';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv,previous=ev)
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):lc.remaining(self.lab,self.plan,inv,ev)
    def test_changed_file_set_blocks_resume(self):
        _,inv=self.inv();(self.folder/'0000000002.idx').write_bytes(idx(self.entries))
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv)
    def test_changed_index_blocks_resume(self):
        _,inv=self.inv();self.index_path.write_bytes(idx(self.entries)+b'x')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv)
    def test_shmem_change_blocks_resume_without_parsing(self):
        p=self.folder/'shmem';p.write_bytes(b'old');_,inv=self.inv();p.write_bytes(b'newer')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv)
    def test_new_plan_same_version_cannot_reuse_checkpoint(self):
        _,inv=self.inv();self.plan=self.make_plan()
        with self.assertRaisesRegex(core.RepairError,'different_plan'):self.verify(inv)
    def test_new_snapshot_cannot_reuse_old_checkpoint(self):
        _,inv=self.inv();_,ev=self.verify(inv,max_candidates=1);_,inv2=self.inv()
        with self.assertRaisesRegex(core.RepairError,'checkpoint_binding_conflict'):self.verify(inv2,previous=ev)
    def test_archive_symlink_rejected(self):
        p=self.folder/'data.000';target=self.base/'external';p.rename(target);p.symlink_to(target)
        with self.assertRaisesRegex(core.RepairError,'link_or_reparse'):self.inv()
    def test_archive_hardlink_rejected(self):
        os.link(self.folder/'data.000',self.base/'shared')
        with self.assertRaisesRegex(core.RepairError,'unshared'):self.inv()
    def test_source_folder_cannot_be_lab(self):
        with self.assertRaisesRegex(core.RepairError,'separate_from_lab'):lc.inventory(self.lab,self.plan,self.lab.root)
    def test_insufficient_space(self):
        with patch.object(lc.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
            with self.assertRaisesRegex(core.RepairError,'insufficient_lab_space'):self.inv()
    def test_candidate_limit_aborts_no_output(self):
        with patch.object(lc,'MAX_CANDIDATES',1):
            with self.assertRaisesRegex(core.RepairError,'candidate_limit'):self.inv()
        self.assertEqual(list((self.lab.root/'objects').glob('local-casc-inventory-*')),[])
    def test_entry_limit_aborts(self):
        with patch.object(lc,'MAX_ENTRIES',1):
            with self.assertRaisesRegex(core.RepairError,'entry_limit'):self.inv()
    def test_index_byte_limit(self):
        with patch.object(lc,'MAX_INDEX',1):
            with self.assertRaisesRegex(core.RepairError,'byte_limit'):self.inv()
    def test_invalid_batch_limits(self):
        _,inv=self.inv()
        for kw in [{'byte_budget':-1},{'byte_budget':True},{'max_candidates':0},{'max_candidates':4097}]:
            with self.assertRaisesRegex(core.RepairError,'batch_limit'):self.verify(inv,**kw)
    def test_cancel_during_batch_preserves_prior_checkpoint(self):
        _,inv=self.inv();_,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes();c=threading.Event()
        def notify(_):c.set()
        outputs=set((self.lab.root/'objects').glob('local-casc-evidence-*.sqlite'))
        with self.assertRaises(core.Cancelled):self.verify(inv,previous=ev,cancel=c,notify=notify)
        self.assertEqual(ev.read_bytes(),before);self.assertEqual(set((self.lab.root/'objects').glob('local-casc-evidence-*.sqlite')),outputs)
        self.assertEqual(list((self.lab.root/'objects').glob('*.part')),[])
    def test_source_change_during_decode_aborts_publication(self):
        _,inv=self.inv()
        def notify(_):
            p=self.folder/'data.000';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv,notify=notify)
        self.assertEqual(list((self.lab.root/'objects').glob('local-casc-evidence-*.sqlite')),[])
    def test_source_change_before_inventory_publication(self):
        def notify(_):
            p=self.folder/'data.000';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.inv(notify=notify)
    def test_share_summary_has_no_private_paths_or_keys(self):
        _,inv=self.inv();_,ev=self.verify(inv);s=json.dumps(lc.remaining(self.lab,self.plan,inv,ev))
        self.assertNotIn(str(self.folder),s)
        for key in self.keys:self.assertNotIn(key.hex(),s)
    def test_actual_process_death_and_resume(self):
        _,inv=self.inv();_,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes()
        script='''import os,sys
from pathlib import Path
import repair_core as core, local_casc as lc
lab=core.Lab(Path(sys.argv[1]))
lc.verify_batch(lab,Path(sys.argv[2]),Path(sys.argv[3]),previous=Path(sys.argv[4]),notify=lambda _:os._exit(73))
'''
        env=dict(os.environ,PYTHONPATH=str(Path(lc.__file__).parent),PYTHONDONTWRITEBYTECODE='1')
        run=subprocess.run([sys.executable,'-B','-c',script,str(self.lab.root),str(self.plan),str(inv),str(ev)],env=env,timeout=20,capture_output=True)
        self.assertEqual(run.returncode,73,run.stderr.decode());self.assertEqual(ev.read_bytes(),before)
        r,_=self.verify(inv,previous=ev);self.assertEqual(r['target_objects_fully_verified_locally'],3)

    def test_no_source_open_for_writing(self):
        original=io.open
        def guard(path,*args,**kw):
            if isinstance(path,(str,Path)):
                p=Path(path)
                if self.folder==p.parent or self.folder in p.parents:
                    mode=args[0] if args else kw.get('mode','r')
                    self.assertFalse(any(c in mode for c in 'wax+'),mode)
            return original(path,*args,**kw)
        with patch('io.open',side_effect=guard):
            _,inv=self.inv();self.verify(inv)
    def test_directory_symlink_rejected(self):
        link=self.base/'linked-storage';link.symlink_to(self.folder,target_is_directory=True)
        with self.assertRaisesRegex(core.RepairError,'link_or_reparse'):
            lc.inventory(self.lab,self.plan,link)
    def test_cancel_before_any_source_read(self):
        c=threading.Event();c.set()
        with patch.object(lc,'_snapshot',side_effect=AssertionError('source access')):
            with self.assertRaises(core.Cancelled):self.inv(cancel=c)
    def test_plan_change_during_inventory_aborts_publication(self):
        changed=[]
        def notify(_):
            if not changed:
                self.sql_change('UPDATE plan SET route_kind=NULL')
                changed.append(True)
        with self.assertRaisesRegex(core.RepairError,'planning_input'):
            self.inv(notify=notify)
        self.assertEqual(list((self.lab.root/'objects').glob('local-casc-inventory-*.sqlite')),[])
    def test_remaining_does_not_accept_other_inventory(self):
        _,inv=self.inv();_,ev=self.verify(inv);_,other=self.inv()
        with self.assertRaisesRegex(core.RepairError,'checkpoint_binding_conflict'):
            lc.remaining(self.lab,self.plan,other,ev)
    def test_checkpoint_low_space_preserves_prior(self):
        _,inv=self.inv();_,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes()
        with patch.object(lc.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
            with self.assertRaisesRegex(core.RepairError,'checkpoint_insufficient_lab_space'):
                self.verify(inv,previous=ev)
        self.assertEqual(ev.read_bytes(),before)
    def test_no_indexes_does_not_establish_absence(self):
        self.index_path.unlink();r,inv=self.inv();v,ev=self.verify(inv)
        self.assertFalse(r['all_observed_index_blocks_verified'])
        self.assertEqual(v['target_objects_fully_verified_locally'],0)
        self.assertEqual(lc.remaining(self.lab,self.plan,inv,ev)['remaining_conditional_transfer_candidates'],3)
    def test_aggregate_index_byte_limit(self):
        with patch.object(lc,'MAX_INDEX_TOTAL',1):
            with self.assertRaisesRegex(core.RepairError,'aggregate_limit'):self.inv()

    def test_offline_demo_end_to_end(self):
        import local_casc_demo
        result=local_casc_demo.run(self.base/'demo-case')
        self.assertTrue(result['success']);self.assertEqual(result['fully_verified_reusable_objects'],2)
        self.assertTrue(result['damaged_fixture_not_subtracted'])
        with self.assertRaisesRegex(core.RepairError,'must_not_exist'):
            local_casc_demo.run(self.base/'demo-case')

if __name__=='__main__':unittest.main()
