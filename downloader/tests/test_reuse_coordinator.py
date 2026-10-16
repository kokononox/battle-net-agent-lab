import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import repair_core as core
import cache_evidence as cache
import legacy_reuse as legacy
import local_casc as local
import reuse_coordinator as reuse
import transfer_routes
import test_local_casc as lt


class ReuseTests(unittest.TestCase):
    make_plan=lt.LocalTests.make_plan
    db=lt.LocalTests.db
    sql_change=lt.LocalTests.sql_change
    source_hashes=lt.LocalTests.source_hashes
    def setUp(self):
        lt.LocalTests.setUp(self)
        self.sql_change("UPDATE plan SET route_kind='archive_range'")
        self.root=self.base/'old-cache';self.root.mkdir()
    def write(self,p,data):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
    def document(self,obj,name='manifest.json'):
        p=self.root/name;p.write_text(json.dumps(obj));return p
    def decoded_import(self,index=0,**changes):
        rel='_retail_/file-%d.bin'%index
        self.write(self.root/rel,self.data[index])
        row={'relative_output':rel,'ckey':self.cks[index].hex(),'decoded_bytes':len(self.data[index]),
             'decoded_sha256':hashlib.sha256(self.data[index]).hexdigest(),'source_root':'Z:/DO-NOT-OPEN'}
        row.update(changes)
        obj={'tool':'WoW Retail Verified Decoded Staging 0.30','status':'all_listed_outputs_staged_and_verified',
             'target_version':'old-unrelated-version','staging_path':'Z:/DO-NOT-OPEN','copy_or_activation_authorized':False,'files':[row]}
        return legacy.Import('decoded_v030',self.document(obj),self.root)
    def encoded_import(self,index=0,**changes):
        rel='Targeted-Staging-'+'a'*16+'/'+self.keys[index].hex()+'.blte'
        self.write(self.root/rel,self.blobs[index])
        row={'relative_output':rel,'ekey':self.keys[index].hex(),'target_ckey':self.cks[index].hex(),
             'encoded_bytes':len(self.blobs[index]),'target_decoded_bytes':len(self.data[index]),
             'encoded_sha256':hashlib.sha256(self.blobs[index]).hexdigest()}
        row.update(changes)
        obj={'cdn_origin':'http://DO-NOT-CONTACT','staging_path':'Z:/DO-NOT-OPEN','files':[row]}
        return legacy.Import('download_v025',self.document(obj),self.root)
    def inv(self,**kw):return reuse.inventory(self.lab,self.plan,**kw)
    def verify(self,inv,**kw):return reuse.verify_batch(self.lab,self.plan,inv,**kw)
    def queue(self,inv,ev):return reuse.make_queue(self.lab,self.plan,inv,ev)
    def local_inputs(self):
        _,inv=local.inventory(self.lab,self.plan,self.folder)
        _,ev=local.verify_batch(self.lab,self.plan,inv)
        return [(inv,ev)]
    def candidate(self,i,kind='encoded',data=None,name=None):
        p=self.root/(name or '%d.%s'%(i,kind));p.write_bytes((self.blobs[i] if kind=='encoded' else self.data[i]) if data is None else data)
        return cache.Candidate(self.keys[i],p,kind)

    def test_v025_fresh_proof_current_binding_and_no_network(self):
        r,inv=self.inv(imports=[self.encoded_import()]);v,ev=self.verify(inv);q,path=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],1);self.assertEqual(q['remaining_conditional_transfer_candidates'],2)
        self.assertFalse(r['old_absolute_paths_or_endpoints_used']);self.assertIsNone(q['required_network_download_bytes'])
        self.assertEqual(reuse.checked_queue(self.lab,self.plan,path),q)
    def test_v030_different_version_same_content_reusable_only_decoded(self):
        _,inv=self.inv(imports=[self.decoded_import()]);_,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['availability_counts']['decoded_content_only'],1)
        self.assertEqual(q['verified_encoded_objects_reusable'],0);self.assertEqual(q['remaining_conditional_transfer_candidates'],3)
    def test_old_receipt_success_assertion_does_not_verify_corrupt_file(self):
        item=self.encoded_import();obj=json.loads(item.manifest.read_text());p=self.root/obj['files'][0]['relative_output'];p.write_bytes(bytes(len(self.blobs[0])))
        _,inv=self.inv(imports=[item]);v,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],0);self.assertIn('candidate_content_mismatch',v['evidence_state_counts'])
    def test_sha256_mismatch_refuses_claim_even_with_target_hash_match(self):
        _,inv=self.inv(imports=[self.encoded_import(encoded_sha256='0'*64)]);v,ev=self.verify(inv)
        self.assertEqual(v['encoded_objects_fully_verified'],0);self.assertIn('legacy_sha256_mismatch',v['evidence_state_counts'])
    def test_decoded_sha_mismatch(self):
        _,inv=self.inv(imports=[self.decoded_import(decoded_sha256='0'*64)]);v,_=self.verify(inv)
        self.assertEqual(v['decoded_target_objects_verified'],0)
    def test_old_claim_not_in_selected_current_target_ignored(self):
        r,inv=self.inv(imports=[self.encoded_import(target_ckey='f'*32)]);self.assertEqual(r['registered_candidates'],0);self.assertEqual(r['legacy_claims_not_in_current_selected_target'],1)
    def test_overlap_encoded_files_subtracted_once(self):
        candidates=[self.candidate(0,name='copy-a'),self.candidate(0,name='copy-b')]
        _,inv=self.inv(explicit=candidates);v,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],1);self.assertEqual(q['verified_encoded_bytes_available'],len(self.blobs[0]))
        self.assertEqual(v['batch_payload_bytes_read'],len(self.blobs[0]))
    def test_overlap_local_and_old_cache_union_not_sum(self):
        local_inputs=self.local_inputs();_,inv=self.inv(explicit=[self.candidate(0),self.candidate(1,'decoded')],local_inputs=local_inputs)
        v,ev=self.verify(inv,byte_budget=0);q,_=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],3);self.assertEqual(q['remaining_conditional_transfer_candidates'],0)
        self.assertEqual(v['batch_payload_bytes_read'],0)
    def test_partial_local_checkpoint_keeps_old_cache_for_other_keys(self):
        _,li=local.inventory(self.lab,self.plan,self.folder);_,le=local.verify_batch(self.lab,self.plan,li,max_candidates=1)
        _,inv=self.inv(explicit=[self.candidate(i) for i in range(3)],local_inputs=[(li,le)])
        v,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],3)
    def test_missing_old_file_not_promoted(self):
        item=self.encoded_import();obj=json.loads(item.manifest.read_text());(self.root/obj['files'][0]['relative_output']).unlink()
        _,inv=self.inv(imports=[item]);v,ev=self.verify(inv,byte_budget=0);q,_=self.queue(inv,ev)
        self.assertEqual(q['verified_encoded_objects_reusable'],0);self.assertIn('source_not_present_at_inventory',v['evidence_state_counts'])
    def test_formerly_missing_file_appears_requires_rebuild(self):
        c=cache.Candidate(self.keys[0],self.root/'absent','encoded');_,inv=self.inv(explicit=[c]);c.path.write_bytes(self.blobs[0])
        with self.assertRaisesRegex(core.RepairError,'reuse_source_changed'):self.verify(inv)
    def test_manifest_over_64k_is_supported_under_4m(self):
        item=self.encoded_import();obj=json.loads(item.manifest.read_text());obj['unused_padding']='x'*900000;item.manifest.write_text(json.dumps(obj))
        _,inv=self.inv(imports=[item]);v,_=self.verify(inv);self.assertEqual(v['encoded_objects_fully_verified'],1)
    def test_json_limit(self):
        item=self.encoded_import();item.manifest.write_bytes(b' '* (legacy.MAX_JSON+1))
        with self.assertRaisesRegex(core.RepairError,'json_size_limit'):self.inv(imports=[item])
    def test_duplicate_json_key(self):
        item=self.encoded_import();item.manifest.write_text('{"files":[],"files":[]}')
        with self.assertRaisesRegex(core.RepairError,'duplicate_json_key'):self.inv(imports=[item])
    def test_traversal_and_windows_paths_rejected(self):
        for path in ('../secret','/secret','C:/secret','a\\b','a:stream','a/CON.txt','a/../b','a//b','a/trailing.'):
            with self.subTest(path=path):
                item=self.decoded_import(relative_output=path)
                with self.assertRaisesRegex(core.RepairError,'relative_path'):self.inv(imports=[item])
    def test_v025_path_key_conflict_rejected(self):
        item=self.encoded_import(relative_output='Targeted-Staging-'+'a'*16+'/'+'f'*32+'.blte')
        with self.assertRaisesRegex(core.RepairError,'v025_output_geometry'):self.inv(imports=[item])
    def test_duplicate_casefold_sources_rejected(self):
        item=self.decoded_import();obj=json.loads(item.manifest.read_text());obj['files'].append(dict(obj['files'][0],relative_output='_RETAIL_/FILE-0.BIN'));item.manifest.write_text(json.dumps(obj))
        with self.assertRaisesRegex(core.RepairError,'duplicate_normalized_source'):self.inv(imports=[item])
    def test_symlink_source_rejected(self):
        c=self.candidate(0);copy=self.root/'outside';c.path.rename(copy);c.path.symlink_to(copy)
        with self.assertRaisesRegex(core.RepairError,'link_or_reparse'):self.inv(explicit=[c])
    def test_hardlink_source_rejected(self):
        c=self.candidate(0);os.link(c.path,self.root/'hardlink')
        with self.assertRaisesRegex(core.RepairError,'unshared'):self.inv(explicit=[c])
    def test_supply_cache_ignores_old_verified_label_and_rechecks(self):
        c=self.candidate(0,data=bytes(len(self.blobs[0])))
        obj={'files':[{'target_ckey':self.cks[0].hex(),'target_decoded_bytes':len(self.data[0]),'alternatives':[{'ekey':self.keys[0].hex(),'encoded_bytes':len(self.blobs[0])}],
            'candidates':[{'kind':'encoded','ekey':self.keys[0].hex(),'source_relative_path':c.path.name,'state':'encoded_target_and_decoded_ckey_verified'}]}]}
        item=legacy.Import('supply_cache',self.document(obj),self.root)
        _,inv=self.inv(imports=[item]);v,_=self.verify(inv);self.assertEqual(v['encoded_objects_fully_verified'],0)
    def test_supply_identical_decoded_alternative_claims_collapse(self):
        c=self.candidate(0,'decoded')
        candidate={'kind':'decoded','source_relative_path':c.path.name}
        record={'target_ckey':self.cks[0].hex(),'target_decoded_bytes':len(self.data[0]),'alternatives':[],
                'candidates':[candidate,dict(candidate)]}
        item=legacy.Import('supply_cache',self.document({'files':[record]}),self.root)
        r,inv=self.inv(imports=[item]);self.assertEqual(r['legacy_claims'],1)
        v,_=self.verify(inv);self.assertEqual(v['decoded_target_objects_verified'],1)
    def test_queue_evidence_change_blocks_checked_read(self):
        _,inv=self.inv(explicit=[self.candidate(0)]);_,ev=self.verify(inv);_,q=self.queue(inv,ev)
        db=sqlite3.connect(ev)
        try:db.execute('UPDATE evidence SET encoded_object_verified=0');db.commit()
        finally:db.close()
        with self.assertRaisesRegex(core.RepairError,'evidence_changed'):
            reuse.checked_queue(self.lab,self.plan,q)
    def test_encoded_sha_second_read_is_budgeted(self):
        _,inv=self.inv(imports=[self.encoded_import()]);v,ev=self.verify(inv,byte_budget=len(self.blobs[0]))
        self.assertEqual(v['candidate_rows_pending'],1);self.assertEqual(v['batch_payload_bytes_read'],0)
        v,_=self.verify(inv,previous=ev,byte_budget=2*len(self.blobs[0]));self.assertEqual(v['batch_payload_bytes_read'],2*len(self.blobs[0]))
    def test_budget_resume_and_prior_unchanged(self):
        _,inv=self.inv(explicit=[self.candidate(i) for i in range(3)]);v,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes()
        v2,ev2=self.verify(inv,previous=ev);q,_=self.queue(inv,ev2)
        self.assertEqual(v2['candidate_rows_pending'],0);self.assertEqual(q['verified_encoded_objects_reusable'],3);self.assertEqual(before,ev.read_bytes())
    def test_source_change_blocks_resume_and_queue_read(self):
        c=self.candidate(0);_,inv=self.inv(explicit=[c]);_,ev=self.verify(inv);_,q=self.queue(inv,ev);c.path.write_bytes(c.path.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'reuse_source_changed'):self.verify(inv,previous=ev)
        with self.assertRaisesRegex(core.RepairError,'reuse_source_changed'):reuse.checked_queue(self.lab,self.plan,q)
    def test_manifest_change_blocks_resume(self):
        item=self.encoded_import();_,inv=self.inv(imports=[item]);item.manifest.write_text('{}')
        with self.assertRaisesRegex(core.RepairError,'reuse_source_changed'):self.verify(inv)
    def test_local_archive_change_blocks_inherited_proof(self):
        inputs=self.local_inputs();_,inv=self.inv(local_inputs=inputs);p=self.folder/'data.000';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'snapshot_changed'):self.verify(inv)
    def test_checkpoint_inventory_binding(self):
        c=self.candidate(0);_,inv=self.inv(explicit=[c]);_,ev=self.verify(inv);_,other=self.inv(explicit=[c])
        with self.assertRaisesRegex(core.RepairError,'checkpoint_binding_conflict'):self.verify(other,previous=ev)
    def test_inventory_different_plan(self):
        _,inv=self.inv(explicit=[self.candidate(0)]);self.plan=self.make_plan()
        with self.assertRaisesRegex(core.RepairError,'inventory_plan_conflict'):self.verify(inv)
    def test_local_checkpoint_different_plan(self):
        inputs=self.local_inputs();self.plan=self.make_plan()
        with self.assertRaisesRegex(core.RepairError,'local_checkpoint_binding_conflict'):self.inv(local_inputs=inputs)
    def test_unknown_route_kept_unresolved_without_reuse(self):
        self.sql_change('UPDATE plan SET route_kind=NULL WHERE ekey=?',(self.keys[0],))
        _,inv=self.inv();_,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['availability_counts']['unresolved_plan'],1)
    def test_unrecognized_route_is_not_a_conditional_direct_guess(self):
        self.sql_change("UPDATE plan SET route_kind='archive' WHERE ekey=?",(self.keys[0],))
        _,inv=self.inv();_,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertEqual(q['availability_counts']['unresolved_plan'],1)
        self.assertEqual(q['remaining_conditional_transfer_candidates'],2)
    def test_pending_is_not_absent_or_verified(self):
        _,inv=self.inv(explicit=[self.candidate(0)]);v,ev=self.verify(inv,byte_budget=0);q,_=self.queue(inv,ev)
        self.assertEqual(q['candidate_rows_pending'],1);self.assertEqual(q['verified_encoded_objects_reusable'],0);self.assertEqual(q['remaining_conditional_transfer_candidates'],3)
    def test_no_source_write_opens(self):
        c=self.candidate(0);before=self.source_hashes();original=io.open
        def guard(path,*args,**kw):
            if isinstance(path,(str,Path)) and self.root in Path(path).parents:
                mode=args[0] if args else kw.get('mode','r');self.assertFalse(any(x in mode for x in 'wax+'))
            return original(path,*args,**kw)
        with patch('io.open',side_effect=guard):_,inv=self.inv(explicit=[c]);_,ev=self.verify(inv);self.queue(inv,ev)
        self.assertEqual(before,self.source_hashes())
    def test_cancel_preserves_previous_checkpoint(self):
        _,inv=self.inv(explicit=[self.candidate(i) for i in range(3)]);_,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes();c=threading.Event()
        with self.assertRaises(core.Cancelled):self.verify(inv,previous=ev,cancel=c,notify=lambda _:c.set())
        self.assertEqual(before,ev.read_bytes())
    def test_source_change_during_verification_no_publication(self):
        c=self.candidate(0);_,inv=self.inv(explicit=[c])
        def notify(_):c.path.write_bytes(c.path.read_bytes()+b'x')
        with self.assertRaisesRegex(core.RepairError,'reuse_source_changed'):self.verify(inv,notify=notify)
        self.assertEqual(list((self.lab.root/'objects').glob('reuse-evidence-*.sqlite')),[])
    def test_low_space_inventory(self):
        with patch.object(reuse.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(core.RepairError,'insufficient_space'):self.inv()
    def test_low_space_checkpoint(self):
        _,inv=self.inv()
        with patch.object(reuse.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(core.RepairError,'insufficient_space'):self.verify(inv)
    def test_summary_excludes_private_paths(self):
        _,inv=self.inv(explicit=[self.candidate(0)]);_,ev=self.verify(inv);q,_=self.queue(inv,ev)
        self.assertNotIn(str(self.root),json.dumps(q));self.assertNotIn(self.keys[0].hex(),json.dumps(q))
    def test_actual_process_death_resume(self):
        _,inv=self.inv(explicit=[self.candidate(i) for i in range(3)]);_,ev=self.verify(inv,max_candidates=1);before=ev.read_bytes()
        script='import sys,os;from pathlib import Path;import repair_core as c,reuse_coordinator as r;r.verify_batch(c.Lab(Path(sys.argv[1])),Path(sys.argv[2]),Path(sys.argv[3]),previous=Path(sys.argv[4]),notify=lambda _:os._exit(74))'
        env=dict(os.environ,PYTHONPATH=str(Path(reuse.__file__).parent),PYTHONDONTWRITEBYTECODE='1')
        p=subprocess.run([sys.executable,'-B','-c',script,str(self.lab.root),str(self.plan),str(inv),str(ev)],env=env,capture_output=True,timeout=20)
        self.assertEqual(p.returncode,74,p.stderr.decode());self.assertEqual(ev.read_bytes(),before)
        v,_=self.verify(inv,previous=ev);self.assertEqual(v['encoded_objects_fully_verified'],3)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.binding=dict(product='wow',region='eu',version='v',build_config='a'*32,cdn_config='b'*32)
        self.target=SimpleNamespace(version='v',build_config='a'*32,cdn_config='b'*32,origins=('https://fixtures.invalid',))
        self.row=dict(ekey=b'e'*16,ckey=b'c'*16,encoded_size=99,decoded_size=100,mapping_state='mapped',transfer_supported=1,
            route_kind='archive_range',archive_key='a'*32,archive_offset=1234,index_key='b'*32)
    def spec(self):return transfer_routes.spec(self.target,self.binding,self.row)
    def test_exact_archive_range_not_guessed_direct(self):
        s=self.spec();self.assertEqual(s.archive_offset,1234);self.assertTrue(s.url.endswith('a'*32));self.assertNotIn(self.row['ekey'].hex(),s.url)
    def test_advertised_direct(self):
        self.row.update(route_kind='advertised_direct',archive_key='',archive_offset=None);s=self.spec();self.assertIsNone(s.archive_offset);self.assertTrue(s.url.endswith(self.row['ekey'].hex()))
    def test_unknown_kind_has_no_direct_fallback(self):
        self.row['route_kind']='archive'
        with self.assertRaisesRegex(core.RepairError,'no_fallback'):self.spec()
    def test_archive_offset_required(self):
        self.row['archive_offset']=None
        with self.assertRaisesRegex(core.RepairError,'offset_required'):self.spec()
    def test_direct_with_archive_geometry_rejected(self):
        self.row['route_kind']='advertised_direct'
        with self.assertRaisesRegex(core.RepairError,'geometry_conflict'):self.spec()
    def test_binding_conflict(self):
        self.target.version='new'
        with self.assertRaisesRegex(core.RepairError,'binding_conflict'):self.spec()
    def test_provenance_required(self):
        self.row['index_key']='z'*32
        with self.assertRaisesRegex(core.RepairError,'provenance_required'):self.spec()
    def test_archive_spec_drives_exact_http_range_and_full_decode(self):
        import tempfile
        import test_repair_core as rt
        data=b'bounded archive range proof'*13;blob,ek=rt.encoded(data,table=True)
        self.row.update(ekey=bytes.fromhex(ek),ckey=hashlib.md5(data).digest(),encoded_size=len(blob),decoded_size=len(data))
        spec=self.spec();transport=rt.Transport(spec,blob)
        with tempfile.TemporaryDirectory() as tmp:
            lab=core.Lab.create(Path(tmp).resolve()/'lab');out=core.fetch_decoded(lab,spec,transport)
            self.assertEqual(out.read_bytes(),data)
        self.assertEqual(transport.requests[0][1]['Range'],'bytes=1234-%d'%(1234+len(blob)-1))
    def test_full_keys_required(self):
        self.row['ekey']=b'e'*9
        with self.assertRaisesRegex(core.RepairError,'full_content_keys_required'):self.spec()

if __name__=='__main__':unittest.main()
