"""Budgeted conditional-queue downloader. Cache ONLY, never game installation.

Fresh official EU binding before and after a normal batch. Per-object immutable
receipts + atomic private session pointer; prefix retained on interruption. No
automatic retry, redirect, origin fallback, asset execution or CASC writes.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import urllib.error
import uuid
import cache_evidence as cache
import plan_storage as store
import repair_core as core
import reuse_coordinator as reuse
import target_metadata as metadata
import transfer_routes

MiB=1024**2


@dataclass(frozen=True)
class Limits:
    max_objects:int=3
    payload_bytes:int=16*MiB
    object_encoded_bytes:int=64*MiB
    decoded_total_bytes:int=256*MiB

    def validate(self):
        for value,low,high in ((self.max_objects,1,64),(self.payload_bytes,0,1024*MiB),
                (self.object_encoded_bytes,1,512*MiB),(self.decoded_total_bytes,0,2*1024*MiB)):
            if type(value)is not int or not low<=value<=high:
                raise core.RepairError('acquisition_limits_invalid')
        return self


def external_workspace(path):
    """Conservative game-root marker guard for caller-chosen Lab locations."""
    path=core.safe(path)
    for ancestor in (path,)+tuple(path.parents):
        if (ancestor/'.build.info').exists() or (ancestor/'.build.db').exists():
            raise core.RepairError('workspace_inside_game_root_or_build_metadata_folder_forbidden')
    return path


def _meta(db,name):return reuse._meta(db,name)


def error_info(exc):
    result={'error_family':type(exc).__name__,'error_code':'unexpected_local_or_transport_error'}
    if isinstance(exc,core.Cancelled):result['error_code']='cancelled'
    elif isinstance(exc,urllib.error.HTTPError):result.update(error_code='http_request_failed',http_status=exc.code)
    elif isinstance(exc,core.RepairError):
        value=str(exc)
        result['error_code']=value if re.fullmatch('[a-zA-Z0-9_]{1,140}',value) else 'safe_validation_failed'
    elif isinstance(exc,sqlite3.Error):result['error_code']='local_database_error'
    elif isinstance(exc,OSError):
        result['error_code']='local_or_network_io_error'
        for k in ('errno','winerror'):
            v=getattr(exc,k,None)
            if type(v)is int:result[k]=v
    return result


def cache_path(lab,spec):
    return core.safe(lab.root/'objects'/('asset-'+spec.ekey+'-'+spec.ckey+'-'+str(spec.encoded_size)+'-'+str(spec.decoded_size)+'.blte'))


def partial_path(lab,spec):
    token=hashlib.sha256(json.dumps(spec.__dict__,sort_keys=True).encode()).hexdigest()
    # Same binding as the prior core's retained encoded partials.
    return core.safe(lab.root/'objects'/(token+'.part'))


def _session_path(lab,queue_path):
    token=hashlib.sha256(queue_path.name.encode()).hexdigest()[:24]
    return core.safe(lab.root/'objects'/('download-session-'+token+'.json'))


def _previous(lab,queue_path,explicit):
    if explicit is not None:return store.owned(lab,explicit)
    pointer=_session_path(lab,queue_path)
    if not pointer.exists():return None
    data=core.load_json(pointer);name=data.get('checkpoint')
    if data.get('format')!='queue-download-session-1' or not isinstance(name,str) or not re.fullmatch(r'transfer-checkpoint-[0-9a-f]{32}\.sqlite',name):
        raise core.RepairError('download_session_pointer_invalid')
    return store.owned(lab,lab.root/'objects'/name)


def _queue_identity(plan,queue_path):
    return {'plan_id':_meta(plan,'plan_id'),'queue_name':queue_path.name,
            'queue_fingerprint':list(core.fingerprint(queue_path.stat()))}


def _completed(lab,previous,binding,identity,cancel):
    """Disk-backed temporary index of unchanged prior receipts; payloads stay on disk.

    Changed/missing completed cache files are queued again, not blindly skipped.
    Fingerprints are not an OS snapshot or malicious-writer guarantee.
    """
    db=sqlite3.connect('')  # disk-backed temporary SQLite, deleted on close
    db.execute('PRAGMA cache_size=-8192')
    try:
        db.execute('CREATE TABLE valid_done(ekey BLOB PRIMARY KEY,path TEXT,fp TEXT)')
        if previous is not None:
            with store.input_db(lab,previous,binding) as (prior,_):
                if _meta(prior,'source_queue_identity')!=identity:
                    raise core.RepairError('transfer_checkpoint_queue_binding_conflict')
                rows=prior.execute('SELECT ekey,ckey,encoded_size,decoded_size,path,fingerprint FROM completed')
                for ek,ck,es,ds,path,fp in rows:
                    core.check(cancel)
                    expected=lab.root/'objects'/('asset-'+ek.hex()+'-'+ck.hex()+'-'+str(es)+'-'+str(ds)+'.blte')
                    if str(expected)!=path:raise core.RepairError('transfer_receipt_cache_path_conflict')
                    p=core.safe(expected)
                    if p.exists() and list(core.fingerprint(core.regular(p).stat()))==json.loads(fp):
                        db.execute('INSERT INTO valid_done VALUES (?,?,?)',(ek,path,fp))
        yield_db=db
        return yield_db
    except BaseException:
        db.close();raise


def _recheck_done(db):
    for path,fp in db.execute('SELECT path,fp FROM valid_done'):
        p=core.safe(path)
        if not p.exists() or list(core.fingerprint(core.regular(p).stat()))!=json.loads(fp):
            raise core.RepairError('completed_download_cache_changed_during_batch')


def _checkpoint(lab,previous,binding,identity,spec,path,cancel,watched=()):
    with store.Writer(lab,'transfer-checkpoint',cancel) as out:
        for source,fp in watched:out.watch(source,fp)
        db=out.db
        db.execute('''CREATE TABLE completed(ekey BLOB PRIMARY KEY,ckey BLOB NOT NULL,
            encoded_size INTEGER NOT NULL,decoded_size INTEGER NOT NULL,path TEXT NOT NULL,
            fingerprint TEXT NOT NULL)''')
        if previous is not None:
            out.watch(previous)
            with store.input_db(lab,previous,binding) as (prior,_):
                if _meta(prior,'source_queue_identity')!=identity:
                    raise core.RepairError('transfer_checkpoint_queue_binding_conflict')
                db.execute('ATTACH DATABASE ? AS old',(previous.as_uri()+'?mode=ro',))
                db.execute('INSERT INTO completed SELECT * FROM old.completed')
        path=core.regular(path);out.watch(path)
        db.execute('INSERT OR REPLACE INTO completed VALUES (?,?,?,?,?,?)',
            (bytes.fromhex(spec.ekey),bytes.fromhex(spec.ckey),spec.encoded_size,spec.decoded_size,
             str(path),json.dumps(list(core.fingerprint(path.stat())))))
        out.metadata('target_binding',binding);out.metadata('source_queue_identity',identity)
    core.atomic_json(_session_path(lab,Path(identity['queue_name'])),
        {'format':'queue-download-session-1','checkpoint':out.path.name})
    return out.path


def _prove(path,spec,cancel):
    state,n,content_ok,encoded_ok,fp=cache._verify(path,'encoded',0,None,
        bytes.fromhex(spec.ekey),spec.encoded_size,bytes.fromhex(spec.ckey),spec.decoded_size,cancel)
    if not content_ok or not encoded_ok:raise core.RepairError('asset_'+state)
    return fp


def _fetch(lab,spec,transport,cancel,budget,notify):
    final=cache_path(lab,spec);part=partial_path(lab,spec)
    if final.exists():
        try:
            _prove(core.regular(final),spec,cancel)
            return final,0,'reverified_owned_encoded_cache'
        except core.Cancelled:raise
        except core.RepairError:
            core.quarantine(core.regular(final))
    resumed=core.regular(part).stat().st_size if part.exists() else 0
    if resumed>spec.encoded_size:
        core.quarantine(part);raise core.RepairError('asset_partial_oversized_retained_in_quarantine')
    remaining=spec.encoded_size-resumed
    if remaining>budget:raise core.RepairError('next_object_exceeds_remaining_payload_budget')
    if shutil.disk_usage(lab.root).free<remaining+64*MiB:
        raise core.RepairError('asset_cache_insufficient_space')
    if remaining:
        start=(spec.archive_offset or 0)+resumed;end=(spec.archive_offset or 0)+spec.encoded_size-1
        headers={'Range':'bytes=%d-%d'%(start,end)} if resumed or spec.archive_offset is not None else {}
        core.check(cancel)
        with transport.open(spec.url,headers) as response:
            core.validate_response(response,spec,resumed)
            with part.open('ab' if resumed else 'xb') as out:
                try:
                    total=resumed
                    while total<spec.encoded_size:
                        core.check(cancel)
                        block=response.read(min(65536,spec.encoded_size-total))
                        if not block:raise core.RepairError('asset_download_interrupted_prefix_retained')
                        if len(block)>spec.encoded_size-total:raise core.RepairError('asset_response_read_contract_violation')
                        out.write(block);total+=len(block)
                        notify(len(block))
                    # Content-Length and exact Range are checked above. Do not
                    # read an extra body byte beyond the explicit payload budget.
                finally:
                    out.flush();os.fsync(out.fileno())
    core.check(cancel)
    try:_prove(core.regular(part),spec,cancel)
    except core.Cancelled:raise
    except core.RepairError:
        core.quarantine(part);raise
    core.check(cancel)
    os.replace(part,final);core.sync_dir(final.parent)
    return final,remaining,('downloaded_and_fully_verified' if remaining else 'retained_partial_fully_verified')


def preview(lab,plan_path,queue_path):
    report=reuse.checked_queue(lab,plan_path,queue_path)
    with store.input_db(lab,queue_path) as (q,_):
        q.row_factory=sqlite3.Row
        row=q.execute('SELECT encoded_size,decoded_size,route_kind FROM queue WHERE conditional_transfer=1 ORDER BY ekey LIMIT 1').fetchone()
        return dict(report,target_version=_meta(q,'target_binding')['version'],next_catalog_candidate=dict(row) if row else None,
                    is_exact_installation_download_requirement=False)


def run_batch(lab,plan_path,queue_path,limits=None,previous=None,transport=None,cancel=None,
              notify=lambda _:None,selected_ekeys=None):
    limits=(limits or Limits()).validate();cancel=cancel or threading.Event();core.check(cancel)
    external_workspace(lab.root)
    transport=transport or core.HTTPS()
    plan_path,queue_path=store.owned(lab,plan_path),store.owned(lab,queue_path)
    if selected_ekeys is not None:
        selected_ekeys=tuple(selected_ekeys)
        if not 1<=len(selected_ekeys)<=64 or len(set(selected_ekeys))!=len(selected_ekeys) or any(not isinstance(k,bytes) or len(k)!=16 for k in selected_ekeys):
            raise core.RepairError('explicit_acquisition_selection_invalid')
    summary={'tool':'WoW Queue Cache Downloader 0.1','scope':'bounded conditional catalog queue; not exact installation deficit',
        'selection_was_explicit':selected_ekeys is not None,'full_install_closure_proven':False,'status':'started','objects_verified_this_batch':0,
        'objects_downloaded_this_batch':0,'objects_reverified_without_asset_network':0,
        'payload_body_bytes_read':0,'payload_body_byte_limit':limits.payload_bytes,
        'object_limit':limits.max_objects,'declared_decoded_bytes_verified':0,
        'official_target_rechecked_at_end':False,'metadata_network_separate_from_payload_budget':True,
        'game_files_modified':False,'assets_executed':False,'CASC_writing_enabled':False,
        'automatic_retry_or_host_fallback':False,'required_network_download_bytes':None,'installation_ready':False}
    checkpoint=None;done=None
    with lab.lock(),store.input_db(lab,plan_path) as (plan,binding),store.input_db(lab,queue_path,binding) as (q,_):
        reuse.checked_queue(lab,plan_path,queue_path)
        identity=_queue_identity(plan,queue_path);checkpoint=_previous(lab,queue_path,previous)
        watched=[(p,core.fingerprint(p.stat())) for p in (plan_path,queue_path)]
        q.row_factory=sqlite3.Row
        try:
            target=metadata.discover(transport,cancel)
            expected=('wow','eu',target.version,target.build_config,target.cdn_config)
            if store.binding_id(binding)!=expected:raise core.RepairError('queue_not_current_official_target_refresh_required')
            summary['target_version']=target.version
            done=_completed(lab,checkpoint,binding,identity,cancel)
            summary['unchanged_prior_receipts_checked']=done.execute('SELECT COUNT(*) FROM valid_done').fetchone()[0]
            # Bounded batches may scan prior completed rows, never load all queue
            # rows into memory. Explicit selections are for controlled tests/API.
            if selected_ekeys is not None:
                missing=q.execute('SELECT COUNT(*) FROM queue WHERE ekey IN ('+','.join('?' for _ in selected_ekeys)+') AND conditional_transfer=1',selected_ekeys).fetchone()[0]
                if missing!=len(selected_ekeys):raise core.RepairError('selected_object_not_conditional_queue_candidate')
                rows=q.execute('SELECT * FROM queue WHERE ekey IN ('+','.join('?' for _ in selected_ekeys)+') ORDER BY ekey',selected_ekeys)
            else:rows=q.execute('SELECT * FROM queue WHERE conditional_transfer=1 ORDER BY ekey')
            status='selected_queue_candidates_complete'
            for row in rows:
                core.check(cancel)
                if done.execute('SELECT 1 FROM valid_done WHERE ekey=?',(row['ekey'],)).fetchone():continue
                if summary['objects_verified_this_batch']>=limits.max_objects:status='object_budget_pause';break
                spec=transfer_routes.spec(target,binding,row)
                if spec.encoded_size>limits.object_encoded_bytes:status='next_object_exceeds_object_size_limit';break
                if summary['declared_decoded_bytes_verified']+spec.decoded_size>limits.decoded_total_bytes:status='decoded_verification_budget_pause';break
                final,part=cache_path(lab,spec),partial_path(lab,spec)
                remaining=spec.encoded_size-(core.regular(part).stat().st_size if part.exists() else 0)
                # Existing final cache is reverified rather than inferred from a
                # decoded cache or a historical filename/success flag.
                if not final.exists() and remaining>limits.payload_bytes-summary['payload_body_bytes_read']:
                    status='payload_budget_pause';break
                reuse.checked_queue(lab,plan_path,queue_path)
                notify({'stage':'object_start','ordinal':summary['objects_verified_this_batch']+1,
                        'encoded_bytes':spec.encoded_size,'remaining_payload_bytes':max(0,remaining)})
                def charge(n):
                    summary['payload_body_bytes_read']+=n
                    notify({'stage':'asset_bytes','payload_body_bytes_read':summary['payload_body_bytes_read']})
                path,n,kind=_fetch(lab,spec,transport,cancel,limits.payload_bytes-summary['payload_body_bytes_read'],charge)
                reuse.checked_queue(lab,plan_path,queue_path)
                _recheck_done(done)
                checkpoint=_checkpoint(lab,checkpoint,binding,identity,spec,path,cancel,watched)
                summary['objects_verified_this_batch']+=1
                summary['objects_downloaded_this_batch']+=int(n>0)
                summary['objects_reverified_without_asset_network']+=int(n==0)
                summary['declared_decoded_bytes_verified']+=spec.decoded_size
                notify({'stage':'object_verified','objects_verified':summary['objects_verified_this_batch']})
            core.check(cancel);reuse.checked_queue(lab,plan_path,queue_path);_recheck_done(done)
            after=metadata.discover(transport,cancel)
            if target.identity()!=after.identity() or target.origins[0] not in after.origins:
                raise core.RepairError('official_target_changed_refresh_required')
            summary.update(status=status,official_target_rechecked_at_end=True)
        except Exception as exc:
            summary.update(status='cancelled_prefix_retained' if isinstance(exc,core.Cancelled) else 'stopped_error',**error_info(exc))
        finally:
            if done is not None:done.close()
        # A sanitized report, not a private receipt. A distinct file per attempt.
        report=core.safe(lab.root/'objects'/('Retail-Queue-Download-to-share-'+uuid.uuid4().hex+'.json'))
        core.atomic_json(report,summary)
    return summary,checkpoint
