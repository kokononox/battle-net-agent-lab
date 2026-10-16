"""Unify freshly verified legacy files and owned local CASC checkpoints.

Encoded evidence is unioned by full EKey, decoded availability by target binding.
No historical success flag, absolute JSON path or old endpoint is trusted.
All sources and exact plan IDs stay bound across immutable batch checkpoints.
Outputs are a conditional acquisition queue, NEVER an install authorization.
"""
import contextlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import uuid
import cache_evidence as cache
import legacy_reuse as legacy
import local_casc as local
import plan_storage as store
import repair_core as core

MAX_CANDIDATES=10_000_000


def _meta(db,name):return local._meta(db,name)


def _observe(path):
    path=core.safe(path)
    if not path.exists():return None
    return list(core.fingerprint(core.regular(path).stat()))


def _stable(snapshot):
    for path,fp in snapshot['files'].items():
        if _observe(Path(path))!=fp:
            raise core.RepairError('reuse_source_changed_rebuild_required')
    for item in snapshot['local_snapshots']:local._stable(item)


class Writer(store.Writer):
    def __init__(self,lab,label,cancel,snapshot):
        super().__init__(lab,label,cancel);self.snapshot=snapshot
    def _check_sources(self):
        super()._check_sources();_stable(self.snapshot)


def inventory(lab,plan_path,imports=(),explicit=(),local_inputs=(),cancel=None,notify=lambda _:None):
    """Register current target candidates, rebind all historical claims to current plan.

    Explicit entries use cache_evidence.Candidate. Only successful owned local
    evidence is inherited, with exact inventory/plan bindings and all source
    checks. Other old evidence DBs are not accepted as cache proof.
    """
    cancel=cancel or threading.Event();core.check(cancel)
    imports=list(imports);explicit=list(explicit);local_inputs=list(local_inputs)
    if len(imports)>32 or len(explicit)>4096 or len(local_inputs)>16:
        raise core.RepairError('reuse_input_count_limit')
    plan_path=store.owned(lab,plan_path);plan_fp=core.fingerprint(plan_path.stat())
    snapshot={'files':{},'local_snapshots':[]}
    with lab.lock(),store.input_db(lab,plan_path) as (plan,binding),contextlib.ExitStack() as stack:
        plan_id=_meta(plan,'plan_id');claims=[];metadata=[]
        for source in imports:
            part,path,fp=legacy.read(source,cancel);claims.extend(part);metadata.append((path,fp))
            if len(claims)>4096:raise core.RepairError('reuse_legacy_claim_limit')
        locals=[]
        for inv_path,ev_path in local_inputs:
            inv_path,ev_path=store.owned(lab,inv_path),store.owned(lab,ev_path)
            inv_fp,ev_fp=core.fingerprint(inv_path.stat()),core.fingerprint(ev_path.stat())
            inv,_=stack.enter_context(store.input_db(lab,inv_path,binding))
            ev,_=stack.enter_context(store.input_db(lab,ev_path,binding))
            if (_meta(inv,'source_plan_id')!=plan_id or _meta(ev,'source_plan_id')!=plan_id or
                    _meta(inv,'source_snapshot_id')!=_meta(ev,'source_snapshot_id')):
                raise core.RepairError('reuse_local_checkpoint_binding_conflict')
            snap=_meta(inv,'local_storage_snapshot');local._stable(snap)
            snapshot['local_snapshots'].append(snap)
            locals.append((inv_path,ev_path,inv_fp,ev_fp,snap))
        needed=plan_path.stat().st_size*3+sum(p[1].stat().st_size for p in locals)*3+64*1024**2
        if shutil.disk_usage(lab.root).free<needed:raise core.RepairError('reuse_inventory_insufficient_space')
        with Writer(lab,'reuse-inventory',cancel,snapshot) as out:
            out.watch(plan_path,plan_fp)
            for path,fp in metadata:out.watch(path,tuple(fp));snapshot['files'][str(path)]=fp
            db=out.db;db.execute('ATTACH DATABASE ? AS p',(plan_path.as_uri()+'?mode=ro',))
            db.executescript('''CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB NOT NULL,
                kind TEXT NOT NULL,source_path TEXT NOT NULL,source_offset INTEGER NOT NULL,
                source_span INTEGER,encoded_size INTEGER NOT NULL,ckey BLOB NOT NULL,
                decoded_size INTEGER NOT NULL,claimed_sha256 TEXT,preverified INTEGER NOT NULL);
                CREATE TEMP TABLE targets AS SELECT ekey,ckey,encoded_size,decoded_size FROM p.plan
                    WHERE mapping_state='mapped' AND transfer_supported=1;
                CREATE INDEX target_ckey ON targets(ckey,decoded_size);
                CREATE UNIQUE INDEX target_ekey ON targets(ekey);''')
            ignored=0
            def add(ek,kind,path,offset,span,es,ck,ds,sha,preverified=0):
                path=core.safe(path);fp=_observe(path);name=str(path)
                if name in snapshot['files'] and snapshot['files'][name]!=fp:
                    raise core.RepairError('reuse_source_changed_during_inventory')
                snapshot['files'][name]=fp
                db.execute('INSERT INTO candidates(ekey,kind,source_path,source_offset,source_span,encoded_size,ckey,decoded_size,claimed_sha256,preverified) VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (ek,kind,name,offset,span,es,ck,ds,sha,preverified))
            for claim in claims:
                core.check(cancel)
                if claim.kind=='decoded':
                    rows=db.execute('SELECT ekey,encoded_size,ckey,decoded_size FROM targets WHERE ckey=? AND decoded_size=? LIMIT 257',
                        (bytes.fromhex(claim.ckey),claim.decoded_size)).fetchall()
                    if len(rows)>256:raise core.RepairError('reuse_decoded_alternative_limit')
                else:
                    rows=db.execute('SELECT ekey,encoded_size,ckey,decoded_size FROM targets WHERE ekey=? AND ckey=? AND encoded_size=? AND decoded_size=?',
                        (bytes.fromhex(claim.ekey),bytes.fromhex(claim.ckey),claim.encoded_size,claim.decoded_size)).fetchall()
                if not rows:ignored+=1
                for ek,es,ck,ds in rows:add(ek,claim.kind,claim.path,0,None,es,ck,ds,claim.sha256)
            for candidate in explicit:
                core.check(cancel)
                if candidate.kind not in ('encoded','decoded','casc_span') or not isinstance(candidate.ekey,bytes) or len(candidate.ekey)!=16:
                    raise core.RepairError('reuse_explicit_candidate_invalid')
                if type(candidate.offset) is not int or candidate.offset<0 or (candidate.span is not None and (type(candidate.span)is not int or candidate.span<0)):
                    raise core.RepairError('reuse_explicit_coordinates_invalid')
                if candidate.kind!='casc_span' and (candidate.offset!=0 or candidate.span is not None):
                    raise core.RepairError('reuse_explicit_coordinates_invalid')
                row=db.execute('SELECT ekey,encoded_size,ckey,decoded_size FROM targets WHERE ekey=?',(candidate.ekey,)).fetchone()
                if not row:raise core.RepairError('reuse_explicit_candidate_not_current_target')
                ek,es,ck,ds=row
                add(ek,candidate.kind,candidate.path,candidate.offset,candidate.span,es,ck,ds,None)
            # Large local proof sets are copied on disk, not materialized in RAM.
            inherited=0
            for number,(inv_path,ev_path,ifp,efp,snap) in enumerate(locals):
                out.watch(inv_path,ifp);out.watch(ev_path,efp)
                # Also retain input DB identity across later batches.
                snapshot['files'][str(inv_path)]=list(ifp);snapshot['files'][str(ev_path)]=list(efp)
                db.execute('ATTACH DATABASE ? AS li',(inv_path.as_uri()+'?mode=ro',))
                db.execute('ATTACH DATABASE ? AS le',(ev_path.as_uri()+'?mode=ro',))
                bad=db.execute('''SELECT COUNT(*) FROM le.evidence e LEFT JOIN li.candidates c ON c.id=e.ordinal
                    LEFT JOIN li.archives a ON a.archive_id=c.archive_id
                    LEFT JOIN targets t ON t.ekey=c.ekey AND t.ckey=c.ckey
                        AND t.encoded_size=c.encoded_size AND t.decoded_size=c.decoded_size
                    WHERE e.encoded_object_verified=1 AND (e.decoded_content_verified!=1 OR
                        c.id IS NULL OR t.ekey IS NULL OR c.ekey!=e.ekey OR
                        a.name IS NULL OR a.ambiguous!=0 OR e.source_path!=?||?||a.name)''',(snap['directory'],os.sep)).fetchone()[0]
                if bad:raise core.RepairError('reuse_local_proof_row_conflict')
                # Paths are already verified by the local snapshot guard. No guessed header geometry.
                before=db.total_changes
                db.execute('''INSERT INTO candidates(ekey,kind,source_path,source_offset,source_span,
                    encoded_size,ckey,decoded_size,claimed_sha256,preverified)
                    SELECT c.ekey,'casc_span',?||?||a.name,c.payload_offset,c.encoded_size,
                        c.encoded_size,c.ckey,c.decoded_size,NULL,1 FROM le.evidence e
                    JOIN li.candidates c ON c.id=e.ordinal JOIN li.archives a ON a.archive_id=c.archive_id
                    WHERE e.encoded_object_verified=1 AND e.decoded_content_verified=1''',(snap['directory'],os.sep))
                inherited+=db.total_changes-before
                # DETACH after an explicit commit; it does not publish the private .part.
                db.commit();db.execute('DETACH DATABASE li');db.execute('DETACH DATABASE le')
            count=db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
            if count>MAX_CANDIDATES:raise core.RepairError('reuse_candidate_limit')
            db.execute('CREATE INDEX candidate_key ON candidates(ekey)')
            result={'registered_candidates':count,'legacy_claims':len(claims),'legacy_claims_not_in_current_selected_target':ignored,
                'inherited_local_full_proofs':inherited,'imported_old_success_flags_as_proof':False,
                'old_absolute_paths_or_endpoints_used':False,'required_network_download_bytes':None,'installation_ready':False}
            out.metadata('target_binding',binding);out.metadata('source_plan_id',plan_id)
            out.metadata('reuse_inventory_id',uuid.uuid4().hex);out.metadata('source_snapshot',snapshot)
            out.metadata('inventory_summary',result)
        return result,out.path


def _proof(row,snapshot,cancel):
    cid,ek,kind,path,offset,span,es,ck,ds,sha,pre=row
    path=Path(path)
    if pre:return 'inherited_local_full_proof',0,True,True
    if snapshot['files'][str(path)] is None:return 'source_not_present_at_inventory',0,False,False
    if kind=='decoded':
        if path.stat().st_size!=ds:return 'candidate_size_mismatch',0,False,False
        digest=core.digest(path,cancel)
        if digest['md5']!=ck.hex():return 'candidate_content_mismatch',ds,False,False
        if sha is not None and digest['sha256']!=sha:return 'legacy_sha256_mismatch',ds,False,False
        return 'decoded_content_verified',ds,True,False
    state,n,content_ok,encoded_ok,fp=cache._verify(path,kind,offset,span,ek,es,ck,ds,cancel)
    if encoded_ok and sha is not None:
        # v0.25 receipt SHA is whole file; second read is explicitly budgeted.
        digest=core.digest(path,cancel);n+=digest['size']
        if digest['sha256']!=sha:return 'legacy_sha256_mismatch',n,False,False
    return state,n,content_ok,encoded_ok


def verify_batch(lab,plan_path,inventory_path,previous=None,cancel=None,byte_budget=2*1024**3,max_candidates=4096,notify=lambda _:None):
    cancel=cancel or threading.Event();core.check(cancel)
    if type(byte_budget)is not int or byte_budget<0 or type(max_candidates)is not int or not 1<=max_candidates<=4096:
        raise core.RepairError('reuse_batch_limit')
    plan_path,inventory_path=store.owned(lab,plan_path),store.owned(lab,inventory_path)
    inputs={p:core.fingerprint(p.stat()) for p in (plan_path,inventory_path)}
    with lab.lock(),store.input_db(lab,plan_path) as (plan,binding),store.input_db(lab,inventory_path,binding) as (inv,_):
        plan_id=_meta(plan,'plan_id');iid=_meta(inv,'reuse_inventory_id')
        if _meta(inv,'source_plan_id')!=plan_id:raise core.RepairError('reuse_inventory_plan_conflict')
        snapshot=_meta(inv,'source_snapshot');_stable(snapshot)
        previous=store.owned(lab,previous) if previous is not None else None
        if shutil.disk_usage(lab.root).free<2*(previous.stat().st_size if previous else 0)+max_candidates*1024+64*1024**2:
            raise core.RepairError('reuse_checkpoint_insufficient_space')
        with Writer(lab,'reuse-evidence',cancel,snapshot) as out:
            for p,fp in inputs.items():out.watch(p,fp)
            db=out.db
            db.executescript('''CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB NOT NULL,
                state TEXT NOT NULL,bytes_read INTEGER NOT NULL,decoded_content_verified INTEGER NOT NULL,
                encoded_object_verified INTEGER NOT NULL);
                CREATE INDEX evidence_key ON evidence(ekey,encoded_object_verified);''')
            cursor=0
            if previous is not None:
                out.watch(previous)
                with store.input_db(lab,previous,binding) as (prev,_):
                    if _meta(prev,'source_plan_id')!=plan_id or _meta(prev,'source_reuse_inventory_id')!=iid:
                        raise core.RepairError('reuse_checkpoint_binding_conflict')
                    cursor=_meta(prev,'last_candidate_id')
                    db.execute('ATTACH DATABASE ? AS prior',(previous.as_uri()+'?mode=ro',))
                    db.execute('INSERT INTO evidence SELECT * FROM prior.evidence')
            prior_completed=db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
            db.execute('ATTACH DATABASE ? AS registered',(inventory_path.as_uri()+'?mode=ro',))
            db.execute('''INSERT OR IGNORE INTO evidence
                SELECT id,ekey,'inherited_local_full_proof',0,1,1
                FROM registered.candidates WHERE preverified=1''')
            count=inv.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
            spent=processed=0;reason=None
            rows=inv.execute('SELECT * FROM candidates WHERE id>? ORDER BY id LIMIT ?',(cursor,max_candidates))
            for row in rows:
                core.check(cancel)
                cid,ek,kind,path,offset,span,es,ck,ds,sha,pre=row
                already=db.execute('SELECT 1 FROM evidence WHERE ekey=? AND encoded_object_verified=1 LIMIT 1',(ek,)).fetchone()
                required=0 if pre or snapshot['files'].get(path,'local') is None else (ds if kind=='decoded' else es*(2 if sha else 1))
                if already:state,n,content_ok,encoded_ok='already_verified_same_target',0,False,False
                elif spent+required>byte_budget:reason='byte_budget_next_candidate_pending';break
                else:
                    notify('Checking registered reuse candidate %d / %d; no game writes.'%(cid,count))
                    if path in snapshot['files'] and _observe(Path(path))!=snapshot['files'][path]:
                        raise core.RepairError('reuse_source_changed_rebuild_required')
                    state,n,content_ok,encoded_ok=_proof(row,snapshot,cancel)
                spent+=n;processed+=1;cursor=cid
                db.execute('INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?,?)',(cid,ek,state,n,content_ok,encoded_ok))
            completed=db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
            if completed<count and reason is None:reason='candidate_batch_limit'
            result={'registered_candidates':count,'candidate_rows_completed':completed,'candidate_rows_pending':count-completed,
                'batch_candidate_rows_completed':completed-prior_completed,'batch_payload_bytes_read':spent,'stop_reason':reason,
                'encoded_objects_fully_verified':db.execute('SELECT COUNT(DISTINCT ekey) FROM evidence WHERE encoded_object_verified=1').fetchone()[0],
                'decoded_target_objects_verified':db.execute('SELECT COUNT(DISTINCT ekey) FROM evidence WHERE decoded_content_verified=1').fetchone()[0],
                'evidence_state_counts':dict(db.execute('SELECT state,COUNT(*) FROM evidence GROUP BY state')),
                'required_network_download_bytes':None,'installation_ready':False}
            out.metadata('target_binding',binding);out.metadata('source_plan_id',plan_id)
            out.metadata('source_reuse_inventory_id',iid);out.metadata('last_candidate_id',cursor)
            out.metadata('verification_summary',result)
        return result,out.path


def make_queue(lab,plan_path,inventory_path,evidence_path,cancel=None):
    """Materialize one decision per full target EKey, never double subtract overlaps."""
    cancel=cancel or threading.Event();core.check(cancel)
    plan_path,inventory_path,evidence_path=[store.owned(lab,p) for p in (plan_path,inventory_path,evidence_path)]
    inputs={p:core.fingerprint(p.stat()) for p in (plan_path,inventory_path,evidence_path)}
    with lab.lock(),store.input_db(lab,plan_path) as (plan,binding),store.input_db(lab,inventory_path,binding) as (inv,_),store.input_db(lab,evidence_path,binding) as (ev,_):
        pid=_meta(plan,'plan_id');iid=_meta(inv,'reuse_inventory_id')
        if _meta(inv,'source_plan_id')!=pid or _meta(ev,'source_plan_id')!=pid or _meta(ev,'source_reuse_inventory_id')!=iid:
            raise core.RepairError('reuse_queue_binding_conflict')
        snapshot=_meta(inv,'source_snapshot');_stable(snapshot)
        if shutil.disk_usage(lab.root).free<plan_path.stat().st_size*3+64*1024**2:raise core.RepairError('reuse_queue_insufficient_space')
        with Writer(lab,'acquisition-queue',cancel,snapshot) as out:
            for p,fp in inputs.items():out.watch(p,fp)
            db=out.db
            db.execute('ATTACH DATABASE ? AS p',(plan_path.as_uri()+'?mode=ro',))
            db.execute('ATTACH DATABASE ? AS e',(evidence_path.as_uri()+'?mode=ro',))
            db.executescript('''CREATE TEMP TABLE proofs AS SELECT ekey,MAX(encoded_object_verified) AS encoded,
                MAX(decoded_content_verified) AS decoded FROM e.evidence GROUP BY ekey;
                CREATE UNIQUE INDEX proofs_key ON proofs(ekey);
                CREATE TABLE queue AS SELECT p.*,
                CASE WHEN v.encoded=1 THEN 'encoded_available'
                     WHEN v.decoded=1 THEN 'decoded_content_only'
                     WHEN p.mapping_state='mapped' AND p.transfer_supported=1 AND p.route_kind IN ('archive_range','advertised_direct')
                          THEN 'conditional_download' ELSE 'unresolved_plan' END AS availability,
                CASE WHEN COALESCE(v.encoded,0)=0 AND p.mapping_state='mapped' AND p.transfer_supported=1
                     AND p.route_kind IN ('archive_range','advertised_direct') THEN 1 ELSE 0 END AS conditional_transfer
                FROM p.plan p LEFT JOIN proofs v USING(ekey);
                CREATE UNIQUE INDEX queue_key ON queue(ekey);''')
            result={'target_objects':db.execute('SELECT COUNT(*) FROM queue').fetchone()[0],
                'availability_counts':dict(db.execute('SELECT availability,COUNT(*) FROM queue GROUP BY availability')),
                'verified_encoded_objects_reusable':db.execute("SELECT COUNT(*) FROM queue WHERE availability='encoded_available'").fetchone()[0],
                'verified_encoded_bytes_available':db.execute("SELECT COALESCE(SUM(encoded_size),0) FROM queue WHERE availability='encoded_available'").fetchone()[0],
                'remaining_conditional_transfer_candidates':db.execute('SELECT COUNT(*) FROM queue WHERE conditional_transfer=1').fetchone()[0],
                'remaining_conditional_encoded_body_bytes':db.execute('SELECT COALESCE(SUM(encoded_size),0) FROM queue WHERE conditional_transfer=1').fetchone()[0],
                'candidate_rows_pending':_meta(ev,'verification_summary')['candidate_rows_pending'],
                'overlapping_sources_counted_once':True,'decoded_content_not_subtracted_as_encoded_representation':True,
                'current_http_availability_proven':False,'required_network_download_bytes':None,'installation_ready':False}
            out.metadata('target_binding',binding);out.metadata('source_plan_id',pid)
            out.metadata('source_reuse_inventory_id',iid);out.metadata('source_snapshot',snapshot)
            out.metadata('private_evidence_inputs', {str(p):list(inputs[p]) for p in (inventory_path,evidence_path)})
            out.metadata('queue_summary',result)
        return result,out.path


def checked_queue(lab,plan_path,queue_path):
    """Read aggregate after source revalidation; consumers must do this again at use."""
    with store.input_db(lab,plan_path) as (plan,binding),store.input_db(lab,queue_path,binding) as (q,_):
        if _meta(plan,'plan_id')!=_meta(q,'source_plan_id'):raise core.RepairError('reuse_queue_plan_conflict')
        _stable(_meta(q,'source_snapshot'))
        for path,fp in _meta(q,'private_evidence_inputs').items():
            path=store.owned(lab,Path(path))
            if _observe(path)!=fp:raise core.RepairError('reuse_queue_evidence_changed')
        return _meta(q,'queue_summary')
