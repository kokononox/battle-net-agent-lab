"""Offline continuation of the pinned local CASC review. No transport or game writes.

Migrate only through the UI queue's exact evidence references, never by newest
filename. Atomic UI pointer after each immutable batch; retain the last two
review checkpoints, seed evidence and every explicitly published queue proof.
"""
import copy
import json
from pathlib import Path
import re
import sqlite3
import threading
import uuid
import acquisition_runner as runner
import local_casc as local
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse

PREFIX={'plan':'content-plan','queue':'acquisition-queue','seed_queue':'acquisition-queue',
        'local_inventory':'local-casc-inventory','seed_local':'local-casc-evidence',
        'latest_local':'local-casc-evidence','seed_inventory':'reuse-inventory','seed_evidence':'reuse-evidence'}


def _pointer(lab):return core.safe(lab.root/'objects'/'downloader-ui-session.json')

def _path(lab,name,prefix):
    if not isinstance(name,str) or not re.fullmatch(re.escape(prefix)+r'-[0-9a-f]{32}\.sqlite',name):
        raise core.RepairError('local_review_owned_filename_required')
    return store.owned(lab,lab.root/'objects'/name)


def _identity(path):return {'name':path.name,'fingerprint':list(core.fingerprint(core.regular(path).stat()))}


def _ref(lab,value,prefix):
    if not isinstance(value,dict):raise core.RepairError('local_review_reference_invalid')
    p=_path(lab,value.get('name'),prefix)
    if value.get('fingerprint')!=list(core.fingerprint(p.stat())):
        raise core.RepairError('local_review_referenced_file_changed')
    return p


def _load(lab):
    path=_pointer(lab);before=core.fingerprint(core.regular(path).stat());data=core.load_json(path)
    if data.get('format')!='queue-downloader-ui-1':raise core.RepairError('ui_session_format_invalid')
    plan=_path(lab,data.get('plan'),'content-plan');q=_path(lab,data.get('queue'),'acquisition-queue')
    if core.fingerprint(core.regular(path).stat())!=before:raise core.RepairError('local_review_session_changed')
    return data,before,plan,q


def _checked(lab,data,plan,q):
    reuse.checked_queue(lab,plan,q)
    record=data.get('local_review')
    if record is None:return None
    if record.get('format')!='offline-local-review-1':raise core.RepairError('local_review_session_format_invalid')
    if _ref(lab,record['plan_file'],'content-plan')!=plan or _ref(lab,record['queue_file'],'acquisition-queue')!=q:
        raise core.RepairError('local_review_ui_pointer_binding_conflict')
    paths={k:_ref(lab,record[k],v) for k,v in PREFIX.items() if k not in ('plan','queue')}
    with store.input_db(lab,plan) as (p,binding),store.input_db(lab,paths['local_inventory'],binding) as (inv,_),store.input_db(lab,paths['latest_local'],binding) as (ev,_):
        if (record.get('plan_id')!=local._meta(p,'plan_id') or local._meta(inv,'source_plan_id')!=record['plan_id'] or
            local._meta(ev,'source_plan_id')!=record['plan_id'] or
            local._meta(inv,'source_snapshot_id')!=local._meta(ev,'source_snapshot_id')):
            raise core.RepairError('local_review_checkpoint_binding_conflict')
        local._stable(local._meta(inv,'local_storage_snapshot'))
    return paths


def _migrate(lab,data,plan,q):
    """Recover the prior GUI's single local inventory/proof, strictly from queue."""
    reuse.checked_queue(lab,plan,q)
    with store.input_db(lab,plan) as (p,binding),store.input_db(lab,q,binding) as (queue,_):
        pid=local._meta(p,'plan_id');snapshot=local._meta(queue,'source_snapshot')
        if len(snapshot['local_snapshots'])!=1:raise core.RepairError('local_review_requires_one_existing_local_snapshot')
        found={}
        for key,prefix in (('local_inventory','local-casc-inventory'),('seed_local','local-casc-evidence')):
            candidates=[]
            for name,fp in snapshot['files'].items():
                path=Path(name)
                if path.parent==lab.root/'objects' and re.fullmatch(prefix+r'-[0-9a-f]{32}\.sqlite',path.name):
                    path=store.owned(lab,path)
                    if list(core.fingerprint(path.stat()))!=fp:raise core.RepairError('local_review_seed_file_changed')
                    candidates.append(path)
            if len(candidates)!=1:raise core.RepairError('local_review_seed_missing_or_ambiguous')
            found[key]=candidates[0]
        inputs=local._meta(queue,'private_evidence_inputs')
        for key,prefix in (('seed_inventory','reuse-inventory'),('seed_evidence','reuse-evidence')):
            candidates=[store.owned(lab,Path(n)) for n in inputs if re.fullmatch(prefix+r'-[0-9a-f]{32}\.sqlite',Path(n).name)]
            if len(candidates)!=1:raise core.RepairError('local_review_seed_reuse_missing_or_ambiguous')
            found[key]=candidates[0]
        found['seed_queue']=q;found['latest_local']=found['seed_local']
        record={'format':'offline-local-review-1','plan_id':pid,'plan_file':_identity(plan),'queue_file':_identity(q),'previous_generated':None,
                'latest_generated':False,'pinned_checkpoints':[],'merged_checkpoint':found['seed_local'].name,
                **{k:_identity(v) for k,v in found.items()}}
    data=copy.deepcopy(data);data['local_review']=record
    _checked(lab,data,plan,q)
    return data


def _publish(lab,data,expected,plan,q):
    # Each lower-level verifier owns its own lock. This lock protects only the
    # compare-and-swap UI pointer, never nests around verify_batch/make_queue.
    with lab.lock():
        if core.fingerprint(core.regular(_pointer(lab)).stat())!=expected:
            raise core.RepairError('local_review_session_changed')
        _checked(lab,data,plan,q)
        core.atomic_json(_pointer(lab),data)
        return core.fingerprint(core.regular(_pointer(lab)).stat())


def _session(lab):
    runner.external_workspace(lab.root)
    data,fp,plan,q=_load(lab)
    if _checked(lab,data,plan,q) is None:
        data=_migrate(lab,data,plan,q);fp=_publish(lab,data,fp,plan,q)
    paths=_checked(lab,data,plan,q)
    return data,fp,plan,q,paths


def _summary(lab,plan,paths):
    with store.input_db(lab,plan) as (_,b),store.input_db(lab,paths['latest_local'],b) as (ev,_):
        return local._meta(ev,'local_verification_summary')


def status(lab):
    data,_,plan,q,paths=_session(lab);s=_summary(lab,plan,paths)
    return {'tool':'WoW Offline Local Review','status':'offline_local_review_status',
            'local_verification_summary':s,'queue_needs_refresh':data['local_review']['merged_checkpoint']!=paths['latest_local'].name,
            'network_requests':0,'game_files_modified':False,'required_network_download_bytes':None,'installation_ready':False}


def queue_needs_refresh(lab):
    # Cheap GUI hint; full fingerprint/source checks happen in worker operations.
    data,_,_,_=_load(lab);r=data.get('local_review')
    return bool(r and r.get('merged_checkpoint')!=r.get('latest_local',{}).get('name'))


def _prune(lab,reference,record):
    if reference is None:return False
    keep={record['seed_local']['name'],record['latest_local']['name'],record.get('merged_checkpoint')}
    keep.update(record.get('pinned_checkpoints',[]))
    if record.get('previous_generated'):keep.add(record['previous_generated']['name'])
    if reference['name'] in keep:return False
    try:
        with lab.lock():
            current,_,_,_=_load(lab)
            # A second process may have published/pinned a newer generation.
            # Never collect using an obsolete in-memory pointer.
            if current.get('local_review')!=record:return False
            p=_ref(lab,reference,'local-casc-evidence');core.regular(p).unlink();core.sync_dir(p.parent);return True
    except (OSError,core.RepairError):return False  # Retain, never risk deleting an unexpected file.


def continue_review(lab,max_batches=32,byte_budget=256*runner.MiB,max_candidates=4096,cancel=None,notify=lambda _:None):
    if type(max_batches)is not int or not 1<=max_batches<=512:raise core.RepairError('local_review_batch_count_invalid')
    if type(byte_budget)is not int or not 1<=byte_budget<=2048*runner.MiB:raise core.RepairError('local_review_byte_budget_invalid')
    if type(max_candidates)is not int or not 1<=max_candidates<=4096:raise core.RepairError('local_review_candidate_budget_invalid')
    cancel=cancel or threading.Event();core.check(cancel)
    data,fp,plan,q,paths=_session(lab);s=_summary(lab,plan,paths);batches=read=pruned=0
    stopped='local_review_batch_limit'
    try:
        for i in range(max_batches):
            core.check(cancel)
            if not s['candidate_rows_pending']:stopped='all_discovered_local_candidates_processed';break
            notify({'stage':'local_read_only','batch':i+1,'batch_limit':max_batches,'local_candidates_pending':s['candidate_rows_pending'],'network_requests':0})
            s,checkpoint=local.verify_batch(lab,plan,paths['local_inventory'],previous=paths['latest_local'],cancel=cancel,
                byte_budget=byte_budget,max_candidates=max_candidates,notify=lambda text:notify({'stage':'local_read_only','message':text,'network_requests':0}))
            new=copy.deepcopy(data);r=new['local_review'];retire=r.get('previous_generated')
            r['previous_generated']=r['latest_local'] if r['latest_generated'] else None
            r['latest_local']=_identity(checkpoint);r['latest_generated']=True
            fp=_publish(lab,new,fp,plan,q);data=new;paths['latest_local']=checkpoint
            batches+=1;read+=s['batch_archive_bytes_read'];pruned+=int(_prune(lab,retire,r))
            notify({'stage':'local_checkpoint_saved','completed_candidates':s['candidate_rows_completed'],
                'local_candidates_pending':s['candidate_rows_pending'],'network_requests':0})
            if not s['candidate_rows_pending']:stopped='all_discovered_local_candidates_processed';break
            if s['batch_candidate_rows_completed']==0:stopped='next_candidate_exceeds_local_read_budget';break
    except core.Cancelled:stopped='cancelled_last_completed_checkpoint_retained'
    report={'tool':'WoW Offline Local Review','status':stopped,'completed_batches_this_run':batches,
            'archive_bytes_read_this_run':read,'superseded_intermediate_checkpoints_removed':pruned,
            'local_verification_summary':_summary(lab,plan,paths),'queue_needs_refresh':data['local_review']['merged_checkpoint']!=paths['latest_local'].name,
            'network_requests':0,'game_files_modified':False,'required_network_download_bytes':None,'installation_ready':False}
    report_path=core.safe(lab.root/'objects'/('Retail-Local-Review-to-share-'+uuid.uuid4().hex+'.json'))
    core.atomic_json(report_path,report)
    return report


def _combined(lab,plan,paths,cancel):
    """Union original claims/proofs and latest full local proof. No payload rereads.

    Seed evidence remains pinned. The source fingerprints for old decoded/encoded
    claims, local file set, and all evidence DBs remain checked by queue consumers.
    """
    _,new_inv=reuse.inventory(lab,plan,local_inputs=[(paths['local_inventory'],paths['latest_local'])],cancel=cancel)
    seed,proof=paths['seed_inventory'],paths['seed_evidence']
    with lab.lock(),store.input_db(lab,plan) as (p,b),store.input_db(lab,seed,b) as (si,_),store.input_db(lab,proof,b) as (se,_),store.input_db(lab,new_inv,b) as (ni,_):
        if (reuse._meta(si,'source_plan_id')!=reuse._meta(p,'plan_id') or reuse._meta(se,'source_reuse_inventory_id')!=reuse._meta(si,'reuse_inventory_id')):
            raise core.RepairError('local_review_seed_reuse_binding_conflict')
        snap=copy.deepcopy(reuse._meta(si,'source_snapshot'));new_snap=reuse._meta(ni,'source_snapshot')
        for path,fp in new_snap['files'].items():
            if path in snap['files'] and snap['files'][path]!=fp:raise core.RepairError('local_review_snapshot_conflict')
            snap['files'][path]=fp
        for s in new_snap['local_snapshots']:
            if s not in snap['local_snapshots']:snap['local_snapshots'].append(s)
        for f in (seed,proof):snap['files'][str(f)]=list(core.fingerprint(f.stat()))
        reuse._stable(snap);offset=si.execute('SELECT COALESCE(MAX(id),0) FROM candidates').fetchone()[0]
        with reuse.Writer(lab,'reuse-inventory',cancel,snap) as out:
            for f in (plan,seed,proof,new_inv):out.watch(f)
            db=out.db;db.execute('ATTACH DATABASE ? AS seed',(seed.as_uri()+'?mode=ro',));db.execute('ATTACH DATABASE ? AS fresh',(new_inv.as_uri()+'?mode=ro',))
            db.execute('''CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB NOT NULL,kind TEXT NOT NULL,
                source_path TEXT NOT NULL,source_offset INTEGER NOT NULL,source_span INTEGER,
                encoded_size INTEGER NOT NULL,ckey BLOB NOT NULL,decoded_size INTEGER NOT NULL,
                claimed_sha256 TEXT,preverified INTEGER NOT NULL)''')
            db.execute('INSERT INTO candidates SELECT * FROM seed.candidates')
            db.execute('INSERT INTO candidates SELECT id+?,ekey,kind,source_path,source_offset,source_span,encoded_size,ckey,decoded_size,claimed_sha256,preverified FROM fresh.candidates',(offset,))
            db.execute('CREATE INDEX candidate_key ON candidates(ekey)')
            out.metadata('target_binding',b);out.metadata('source_plan_id',reuse._meta(p,'plan_id'));iid=uuid.uuid4().hex;out.metadata('reuse_inventory_id',iid)
            out.metadata('source_snapshot',snap);out.metadata('inventory_summary',{'registered_candidates':db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0],'offline_extension':True,'installation_ready':False})
        combined=out.path
        with reuse.Writer(lab,'reuse-evidence',cancel,snap) as out:
            for f in (plan,seed,proof,combined):out.watch(f)
            db=out.db;db.execute('ATTACH DATABASE ? AS seed',(proof.as_uri()+'?mode=ro',))
            db.executescript('''CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB NOT NULL,state TEXT NOT NULL,
                bytes_read INTEGER NOT NULL,decoded_content_verified INTEGER NOT NULL,encoded_object_verified INTEGER NOT NULL);
                CREATE INDEX evidence_key ON evidence(ekey,encoded_object_verified);
                INSERT INTO evidence SELECT * FROM seed.evidence;''')
            out.metadata('target_binding',b);out.metadata('source_plan_id',reuse._meta(p,'plan_id'));out.metadata('source_reuse_inventory_id',iid)
            out.metadata('last_candidate_id',reuse._meta(se,'last_candidate_id'))
        inherited=out.path
    # Inserts all new preverified local proof rows. At most one bounded batch for
    # any original claims that were pending; no metadata network is possible.
    summary,evidence=reuse.verify_batch(lab,plan,combined,previous=inherited,cancel=cancel,byte_budget=256*runner.MiB)
    return summary,combined,evidence


def refresh_queue(lab,cancel=None,notify=lambda _:None):
    cancel=cancel or threading.Event();core.check(cancel)
    data,fp,plan,q,paths=_session(lab)
    notify({'stage':'queue_rebuild_offline','network_requests':0})
    verify,inv,ev=_combined(lab,plan,paths,cancel)
    summary,new_queue=reuse.make_queue(lab,plan,inv,ev,cancel)
    new=copy.deepcopy(data);new['queue']=new_queue.name;r=new['local_review'];r['queue_file']=_identity(new_queue);r['merged_checkpoint']=paths['latest_local'].name
    if r['merged_checkpoint'] not in r['pinned_checkpoints']:r['pinned_checkpoints'].append(r['merged_checkpoint'])
    _publish(lab,new,fp,plan,new_queue)
    report={'tool':'WoW Offline Local Review','status':'conditional_queue_refreshed_offline',
            'local_verification_summary':_summary(lab,plan,paths),'reuse_verification_summary':verify,'queue_summary':summary,
            'queue_needs_refresh':False,'network_requests':0,'game_files_modified':False,
            'required_network_download_bytes':None,'installation_ready':False}
    core.atomic_json(core.safe(lab.root/'objects'/('Retail-Local-Review-to-share-'+uuid.uuid4().hex+'.json')),report)
    return report,plan,new_queue
