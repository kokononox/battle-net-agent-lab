import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import acquisition_runner as ar
import downloader_controller as ui
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse
import target_metadata as meta
import transfer_routes
import test_repair_core as rt
import test_download_inventory as dt
import test_content_plan as pt


class Service:
    def __init__(self,binding,archive,blobs):
        self.archive=archive;self.blobs=blobs;self.requests=[];self.cut=None
        self.mutate=None;self.http_error=None;self.edit=lambda r:r;self.cancel_on_bytes=None
        self.version=binding['version'];self.bk=binding['build_config'];self.dk=binding['cdn_config']
    def open(self,url,headers):
        self.requests.append((url,dict(headers)))
        if url==meta.VERSIONS:
            data=('Region|BuildConfig|CDNConfig|BuildId|VersionsName\neu|%s|%s|70391|%s\n'%(self.bk,self.dk,self.version)).encode()
            return dt.Response(data,url)
        if url==meta.CDNS:return dt.Response(b'Name|Path|Servers\neu|tpr/wow|https://fixtures.invalid\n',url)
        if self.http_error:raise HTTPError(url,self.http_error,'blocked',{},None)
        if self.mutate:self.mutate()
        key=url.rsplit('/',1)[-1]
        data=self.archive if key=='a'*32 else self.blobs[key]
        if 'Range' in headers:
            a,b=map(int,headers['Range'][6:].split('-'));body=data[a:b+1]
            h={'Content-Length':str(len(body)),'Content-Range':'bytes %d-%d/%d'%(a,b,len(data))};status=206
        else:body=data;h={'Content-Length':str(len(body))};status=200
        if self.cut is not None:body=body[:self.cut]
        r=dt.Response(body,url,status,h)
        if self.cancel_on_bytes:
            original=r.read
            def read(n):
                block=original(min(n,10))
                if block:self.cancel_on_bytes.set()
                return block
            r.read=read
        return self.edit(r)
    def asset_requests(self):return [(u,h) for u,h in self.requests if '/data/' in u]


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.lab=core.Lab.create(self.base/'lab')
        self.data=[b'synthetic A'*33,b'synthetic B'*49,b'synthetic direct'*27]
        pairs=[rt.encoded(d,table=i==1) for i,d in enumerate(self.data)]
        self.blobs=[p[0] for p in pairs];self.keys=[bytes.fromhex(p[1]) for p in pairs]
        self.cks=[hashlib.md5(d).digest() for d in self.data]
        self.binding=dict(product='wow',region='eu',version='12.1.5.70391',build_config='b'*32,cdn_config='c'*32)
        self.archive=bytearray(5000);self.offsets=[300,1400,2600]
        with store.Writer(self.lab,'content-plan',threading.Event()) as out:
            out.db.execute('''CREATE TABLE plan(ekey BLOB PRIMARY KEY,ckey BLOB,encoded_size INTEGER,
                decoded_size INTEGER,mapping_state TEXT,transfer_supported INTEGER,route_kind TEXT,
                archive_key TEXT,archive_offset INTEGER,index_key TEXT)''')
            for i,ek in enumerate(self.keys):
                off=self.offsets[i];blob=self.blobs[i];self.archive[off:off+len(blob)]=blob
                out.db.execute('INSERT INTO plan VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (ek,self.cks[i],len(blob),len(self.data[i]),'mapped',1,
                     'archive_range' if i<2 else 'advertised_direct','a'*32 if i<2 else '',off if i<2 else None,'d'*32))
            out.metadata('target_binding',self.binding);out.metadata('plan_id',out.path.stem)
        self.plan=out.path
        _,inv=reuse.inventory(self.lab,self.plan);_,ev=reuse.verify_batch(self.lab,self.plan,inv)
        _,self.queue=reuse.make_queue(self.lab,self.plan,inv,ev)
        self.net=Service(self.binding,bytes(self.archive),{k.hex():b for k,b in zip(self.keys,self.blobs)})
    def runit(self,**kwargs):return ar.run_batch(self.lab,self.plan,self.queue,transport=self.net,**kwargs)
    def target(self):return meta.Target(self.binding['version'],70391,self.binding['build_config'],self.binding['cdn_config'],('https://fixtures.invalid',))
    def spec(self,i):
        with store.input_db(self.lab,self.queue) as (q,_):
            q.row_factory=sqlite3.Row;row=q.execute('SELECT * FROM queue WHERE ekey=?',(self.keys[i],)).fetchone()
            return transfer_routes.spec(self.target(),self.binding,row)
    def limits(self,n=3,b=1024**2):return ar.Limits(n,b)
    def selected(self,i):return {'selected_ekeys':(self.keys[i],)}
    def report(self,p):
        with store.input_db(self.lab,p) as (d,_):return d.execute('SELECT COUNT(*) FROM completed').fetchone()[0]

    def test_full_bounded_batch_exact_range_and_direct_proofs(self):
        r,cp=self.runit(limits=self.limits())
        self.assertEqual(r['objects_verified_this_batch'],3);self.assertEqual(r['payload_body_bytes_read'],sum(map(len,self.blobs)))
        self.assertEqual(self.report(cp),3);self.assertTrue(r['official_target_rechecked_at_end'])
        self.assertEqual(len(self.net.asset_requests()),3)
        self.assertTrue(any('Range' in h for _,h in self.net.asset_requests()))
        self.assertTrue(any(not h for _,h in self.net.asset_requests()))
        self.assertFalse(r['installation_ready']);self.assertEqual(list((self.lab.root/'target').iterdir()),[])
    def test_byte_limit_exact_not_one_probe_byte_more(self):
        r,_=self.runit(limits=self.limits(1,len(self.blobs[0])),**self.selected(0))
        self.assertEqual(r['payload_body_bytes_read'],len(self.blobs[0]));self.assertEqual(r['objects_verified_this_batch'],1)
    def test_too_small_budget_no_asset_request(self):
        r,cp=self.runit(limits=self.limits(1,len(self.blobs[0])-1),**self.selected(0))
        self.assertEqual(r['status'],'payload_budget_pause');self.assertIsNone(cp);self.assertEqual(self.net.asset_requests(),[])
    def test_object_budget_and_automatic_pointer_resume(self):
        r,cp=self.runit(limits=self.limits(1));before=cp.read_bytes();self.assertEqual(r['status'],'object_budget_pause')
        r2,cp2=self.runit(limits=self.limits());self.assertEqual(r2['objects_verified_this_batch'],2)
        self.assertEqual(self.report(cp2),3);self.assertEqual(before,cp.read_bytes())
    def test_completed_resume_has_no_asset_requests(self):
        self.runit();self.net.requests.clear();r,_=self.runit()
        self.assertEqual(r['objects_verified_this_batch'],0);self.assertEqual(self.net.asset_requests(),[])
    def test_interrupted_prefix_then_precise_resume(self):
        self.net.cut=11;r,cp=self.runit(**self.selected(0));spec=self.spec(0)
        self.assertIsNone(cp);self.assertEqual(ar.partial_path(self.lab,spec).stat().st_size,11)
        self.assertEqual(r['payload_body_bytes_read'],11);self.assertEqual(r['status'],'stopped_error')
        self.net.cut=None;self.net.requests.clear();r,cp=self.runit(**self.selected(0))
        self.assertEqual(self.net.asset_requests()[0][1]['Range'],'bytes=%d-%d'%(self.offsets[0]+11,self.offsets[0]+len(self.blobs[0])-1))
        self.assertEqual(r['payload_body_bytes_read'],len(self.blobs[0])-11);self.assertEqual(self.report(cp),1)
    def test_direct_partial_resume_range_is_bound_to_object(self):
        self.net.cut=13;self.runit(**self.selected(2));self.net.cut=None;self.net.requests.clear();r,_=self.runit(**self.selected(2))
        self.assertEqual(self.net.asset_requests()[0][1]['Range'],'bytes=13-%d'%(len(self.blobs[2])-1));self.assertEqual(r['objects_verified_this_batch'],1)
    def test_cancel_prefix_retained_no_final_metadata(self):
        c=threading.Event();self.net.cancel_on_bytes=c;r,cp=self.runit(cancel=c,**self.selected(0))
        self.assertEqual(r['status'],'cancelled_prefix_retained');self.assertIsNone(cp)
        self.assertEqual(ar.partial_path(self.lab,self.spec(0)).stat().st_size,10)
        self.assertEqual(len(self.net.requests),3)
    def test_cancel_before_start_no_network(self):
        c=threading.Event();c.set()
        with self.assertRaises(core.Cancelled):self.runit(cancel=c)
        self.assertEqual(self.net.requests,[])
    def test_decoded_cache_alone_does_not_count_as_encoded_download(self):
        p=self.lab.root/'objects'/(self.cks[0].hex()+'-'+str(len(self.data[0]))+'.decoded');p.write_bytes(self.data[0])
        r,_=self.runit(**self.selected(0));self.assertEqual(r['objects_downloaded_this_batch'],1);self.assertEqual(len(self.net.asset_requests()),1)
    def test_owned_final_cache_without_receipt_is_fully_reverified(self):
        final=ar.cache_path(self.lab,self.spec(0));final.write_bytes(self.blobs[0])
        r,cp=self.runit(limits=self.limits(1,0),**self.selected(0))
        self.assertEqual(r['objects_reverified_without_asset_network'],1);self.assertEqual(self.net.asset_requests(),[]);self.assertEqual(self.report(cp),1)
    def test_corrupted_completed_cache_is_not_blindly_skipped(self):
        self.runit(**self.selected(0));p=ar.cache_path(self.lab,self.spec(0));p.write_bytes(bytes(len(self.blobs[0])))
        self.net.requests.clear();r,_=self.runit(**self.selected(0))
        self.assertEqual(r['objects_downloaded_this_batch'],1);self.assertEqual(p.read_bytes(),self.blobs[0]);self.assertEqual(len(self.net.asset_requests()),1)
    def test_corrupt_partial_fails_proof_and_no_automatic_retry(self):
        p=ar.partial_path(self.lab,self.spec(0));p.write_bytes(b'wrongprefix')
        r,cp=self.runit(**self.selected(0));self.assertIsNone(cp);self.assertEqual(r['objects_verified_this_batch'],0)
        self.assertEqual(len(self.net.asset_requests()),1);self.assertTrue(list(p.parent.glob(p.name+'.rejected-*')))
    def test_oversized_partial_retained_no_request(self):
        p=ar.partial_path(self.lab,self.spec(0));p.write_bytes(b'x'*(len(self.blobs[0])+1));r,_=self.runit(**self.selected(0))
        self.assertEqual(len(self.net.asset_requests()),0);self.assertIn('partial_oversized',r['error_code'])
    def test_http403_no_retry_no_fallback_no_receipt(self):
        self.net.http_error=403;r,cp=self.runit(**self.selected(0))
        self.assertEqual(r['http_status'],403);self.assertIsNone(cp);self.assertEqual(len(self.net.asset_requests()),1)
    def test_ignored_range_rejected_before_body(self):
        def edit(r):r.status=200;return r
        self.net.edit=edit;r,cp=self.runit(**self.selected(0));self.assertIsNone(cp);self.assertEqual(r['payload_body_bytes_read'],0)
    def test_wrong_content_range_rejected(self):
        def edit(r):r.headers['Content-Range']='bytes 0-1/2';return r
        self.net.edit=edit;r,_=self.runit(**self.selected(0));self.assertEqual(r['objects_verified_this_batch'],0)
    def test_wrong_content_length_rejected(self):
        def edit(r):r.headers['Content-Length']='1000000000';return r
        self.net.edit=edit;r,_=self.runit(**self.selected(0));self.assertEqual(r['payload_body_bytes_read'],0)
    def test_bad_payload_retained_not_published(self):
        self.net.archive=bytes(len(self.archive));r,cp=self.runit(**self.selected(0))
        self.assertIsNone(cp);self.assertFalse(ar.cache_path(self.lab,self.spec(0)).exists());self.assertEqual(r['objects_verified_this_batch'],0)
    def test_target_changed_before_assets_stops(self):
        self.net.version='12.1.5.70392';r,cp=self.runit()
        self.assertIsNone(cp);self.assertEqual(self.net.asset_requests(),[]);self.assertIn('version_build_id',r['error_code'])
    def test_config_changed_before_assets_stops(self):
        self.net.bk='e'*32;r,_=self.runit();self.assertEqual(self.net.asset_requests(),[]);self.assertIn('not_current_official',r['error_code'])
    def test_target_changes_after_object_retains_bound_checkpoint(self):
        self.net.mutate=lambda:setattr(self.net,'bk','e'*32)
        r,cp=self.runit(**self.selected(0));self.assertEqual(self.report(cp),1);self.assertFalse(r['official_target_rechecked_at_end']);self.assertIn('target_changed',r['error_code'])
    def test_decoded_total_budget_blocks_before_asset(self):
        r,_=self.runit(limits=ar.Limits(3,1024**2,64*ar.MiB,0));self.assertEqual(r['status'],'decoded_verification_budget_pause');self.assertEqual(self.net.asset_requests(),[])
    def test_object_size_guard(self):
        r,_=self.runit(limits=ar.Limits(3,1024**2,1));self.assertIn('object_size_limit',r['status']);self.assertEqual(self.net.asset_requests(),[])
    def test_limits_validate_no_boolean_or_unbounded_values(self):
        for limits in (ar.Limits(True),ar.Limits(0),ar.Limits(65),ar.Limits(payload_bytes=-1),ar.Limits(payload_bytes=1025*ar.MiB)):
            with self.assertRaises(core.RepairError):self.runit(limits=limits)
    def test_explicit_selection_must_be_queue_candidate(self):
        r,_=self.runit(selected_ekeys=(b'x'*16,));self.assertIn('not_conditional',r['error_code']);self.assertEqual(self.net.asset_requests(),[])
    def test_receipt_cannot_be_reused_for_another_queue(self):
        _,cp=self.runit(**self.selected(0));_,inv=reuse.inventory(self.lab,self.plan);_,ev=reuse.verify_batch(self.lab,self.plan,inv);_,newq=reuse.make_queue(self.lab,self.plan,inv,ev)
        self.queue=newq;self.net.requests.clear();r,_=self.runit(previous=cp)
        self.assertIn('queue_binding_conflict',r['error_code']);self.assertEqual(self.net.asset_requests(),[])
    def test_session_pointer_cannot_escape_objects(self):
        p=ar._session_path(self.lab,self.queue);core.atomic_json(p,{'format':'queue-download-session-1','checkpoint':'../../outside.sqlite'})
        with self.assertRaisesRegex(core.RepairError,'pointer_invalid'):self.runit()
        self.assertEqual(self.net.requests,[])
    def test_preview_no_network_and_not_exact_patch_claim(self):
        r=ar.preview(self.lab,self.plan,self.queue);self.assertFalse(r['is_exact_installation_download_requirement']);self.assertEqual(self.net.requests,[])
    def test_share_report_excludes_paths_keys_urls(self):
        r,_=self.runit(**self.selected(0));text=json.dumps(r)
        self.assertNotIn(str(self.lab.root),text);self.assertNotIn(self.keys[0].hex(),text);self.assertNotIn('https://',text)
        self.assertTrue(list((self.lab.root/'objects').glob('Retail-Queue-Download-to-share-*.json')))
    def test_asset_cache_symlink_rejected_without_outside_write(self):
        external=self.base/'external';external.write_bytes(b'private');ar.cache_path(self.lab,self.spec(0)).symlink_to(external)
        r,_=self.runit(**self.selected(0));self.assertEqual(r['objects_verified_this_batch'],0);self.assertEqual(external.read_bytes(),b'private')
    def test_low_space_stops_before_asset_request(self):
        with patch.object(ar.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):r,_=self.runit(**self.selected(0))
        self.assertEqual(r['objects_verified_this_batch'],0);self.assertEqual(self.net.asset_requests(),[])
    def test_actual_process_death_after_receipt_then_resume(self):
        # Kill after the first durable object receipt. Receipt/pointer and OS lock
        # survive as intended; no game/target files were written.
        script='''import sys,os
from pathlib import Path
import acquisition_runner as a,repair_core as c
from test_acquisition_runner import Service
import json
base=Path(sys.argv[1]);config=json.loads((base/'fixture.json').read_text())
net=Service(config['binding'],bytes.fromhex(config['archive']),config['blobs'])
net.blobs={k:bytes.fromhex(v) for k,v in net.blobs.items()}
a.run_batch(c.Lab(base/'lab'),Path(config['plan']),Path(config['queue']),transport=net,
 notify=lambda e:os._exit(75) if e['stage']=='object_verified' else None)
'''
        config=dict(binding=self.binding,archive=bytes(self.archive).hex(),blobs={k.hex():b.hex() for k,b in zip(self.keys,self.blobs)},plan=str(self.plan),queue=str(self.queue))
        (self.base/'fixture.json').write_text(json.dumps(config))
        env=dict(os.environ,PYTHONPATH=os.pathsep.join((str(Path(ar.__file__).parent),str(Path(__file__).parent))),PYTHONDONTWRITEBYTECODE='1')
        p=subprocess.run([sys.executable,'-B','-c',script,str(self.base)],env=env,capture_output=True,timeout=20)
        self.assertEqual(p.returncode,75,p.stderr.decode());r,cp=self.runit()
        self.assertEqual(r['objects_verified_this_batch'],2);self.assertEqual(self.report(cp),3)


class ControllerTests(unittest.TestCase):
    def test_parser_limits(self):
        self.assertEqual(ui.parse_limits('3','16').payload_bytes,16*ar.MiB)
        for a,b in [('0','16'),('65','16'),('3','0'),('3','1025'),('-1','16'),('3','1.5')]:
            with self.assertRaises(core.RepairError):ui.parse_limits(a,b)
    def test_gui_module_import_has_no_tk_or_network_side_effect(self):
        with patch.object(core,'HTTPS',side_effect=AssertionError('network initialization')):
            module=importlib.import_module('windows_app');self.assertTrue(callable(module.main))
    def test_display_labels_conditional_catalog_not_patch(self):
        text=ui.display_preview({'target_objects':3,'remaining_conditional_transfer_candidates':3})
        self.assertIn('مشروط',text);self.assertIn('حجم آپدیت لازم تو را مشخص نمی‌کنند',text)
    def test_error_message_sanitized(self):
        result=ar.error_info(OSError('SECRET C:/Users/private/token'))
        self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn('private',json.dumps(result))
    def test_new_lab_inside_recognized_game_root_refused_before_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            game=Path(tmp).resolve()/'game';game.mkdir();(game/'.build.info').write_text('not modified')
            destination=game/'new-lab'
            with self.assertRaisesRegex(core.RepairError,'workspace_inside_game_root'):
                ui.new_lab(destination)
            self.assertFalse(destination.exists());self.assertEqual((game/'.build.info').read_text(),'not modified')
    def test_controller_low_space_no_metadata_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=core.Lab.create(Path(tmp).resolve()/'lab');net=pt.NormalChain()
            with patch.object(ui.shutil,'disk_usage',return_value=type('D',(),{'free':0})()):
                with self.assertRaisesRegex(core.RepairError,'5_GiB'):ui.prepare(lab,transport=net)
            self.assertEqual(net.requests,[])
    def test_full_preparation_pipeline_and_owned_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=core.Lab.create(Path(tmp).resolve()/'lab');net=pt.NormalChain()
            report,p,q=ui.prepare(lab,transport=net)
            self.assertEqual(ui.load_state(lab),(p,q));self.assertFalse(report['installation_ready'])
            self.assertEqual(report['queue_summary']['target_objects'],3)
            self.assertTrue(all(ek.hex() not in url for url,_ in net.requests for ek in net.keys))
            self.assertEqual(list((lab.root/'target').iterdir()),[])
    def test_load_state_cannot_follow_external_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=core.Lab.create(Path(tmp).resolve()/'lab');core.atomic_json(ui._state_path(lab),{'format':'queue-downloader-ui-1','plan':'../../external','queue':'q'})
            with self.assertRaisesRegex(core.RepairError,'owned_filename'):ui.load_state(lab)

if __name__=='__main__':unittest.main()
