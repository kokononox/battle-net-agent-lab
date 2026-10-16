"""Offline PA -> exact saved local CASC evidence binding. No network/payload reads.

Standalone read-only adapter for queue-downloader-ui-1/offline-local-review-1.
No migration, queue update, archive reads, game writer or patch authorization.
"""
from __future__ import annotations
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from datetime import datetime, timezone
import patch_audit as a

# Limited offline evidence-binding policy, not a CDN routing policy. Both
# configuration identities were obtained and MD5-checked from official HTTPS.
SAVED_CDN = '837a654343ce719ad447e92a6c0b557f'
OFFLINE_CDN_IDENTITIES = frozenset((a.CDN, SAVED_CDN))

class BindingError(ValueError): pass

def need(condition, code):
    if not condition: raise BindingError(code)

def fp(s):
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink]

def safe(path, regular=False):
    p=Path(os.path.abspath(str(path)))
    for item in reversed((p,)+tuple(p.parents)):
        s=item.lstat()
        need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'link_or_reparse_point')
        if item!=p:need(stat.S_ISDIR(s.st_mode),'non_directory_ancestor')
    if regular:
        s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'regular_unshared_file_required')
    return p

def json_object(b):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate_json_key');out[k]=v
        return out
    try:
        obj=json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(BindingError('nonfinite_json')))
    except (ValueError,UnicodeError) as e:
        if isinstance(e,BindingError):raise
        raise BindingError('invalid_json') from None
    need(isinstance(obj,dict),'json_object_required')
    return obj

class Watch:
    def __init__(self):self.files={};self.dirs={};self.databases=[]
    def file(self,p,expected=None):
        p=safe(p,True);now=fp(p.stat())
        if expected is not None:need(now==expected,'saved_file_fingerprint_changed')
        if p in self.files:need(now==self.files[p],'source_changed')
        self.files[p]=now
        return p
    def read(self,p,limit=8*1024**2):
        p=self.file(p);before=self.files[p]
        need(before[2]<=limit,'metadata_file_limit')
        with p.open('rb') as f:
            need(fp(os.fstat(f.fileno()))==before,'source_changed')
            b=f.read(limit+1)
            need(fp(os.fstat(f.fileno()))==before,'source_changed')
        need(len(b)<=limit and len(b)==before[2],'metadata_file_changed')
        self.check();return b
    def snapshot(self,snapshot):
        need(isinstance(snapshot,dict) and set(snapshot)>={'directory','files','names','directory_identity'},'snapshot_shape')
        folder=safe(snapshot['directory']);need(folder.is_dir(),'snapshot_directory')
        names=snapshot['names'];files=snapshot['files']
        need(isinstance(names,list) and len(names)<=20000 and all(isinstance(n,str) and n not in ('.','..') and '/' not in n and '\\' not in n for n in names),'snapshot_names')
        need(isinstance(files,dict) and set(files).issubset(set(names)),'snapshot_files')
        need(sorted(os.listdir(folder))==names and fp(folder.stat())==snapshot['directory_identity'],'local_storage_snapshot_changed')
        self.dirs[folder]=(names,snapshot['directory_identity'])
        for name,expected in files.items():self.file(folder/name,expected)
        return folder
    def check(self):
        for p in self.databases:
            need(not any(Path(str(p)+suffix).exists() for suffix in ('-wal','-shm','-journal')),'database_sidecar_present')
        for p,before in self.files.items():need(fp(safe(p,True).stat())==before,'source_changed')
        for p,(names,before) in self.dirs.items():
            need(sorted(os.listdir(safe(p)))==names and fp(p.stat())==before,'local_storage_snapshot_changed')

def metadata(db,alias,name):
    row=db.execute('SELECT value FROM '+alias+'.metadata WHERE name=?',(name,)).fetchone()
    need(row is not None,'metadata_field_missing')
    try:return json.loads(row[0])
    except (ValueError,TypeError):raise BindingError('invalid_database_metadata') from None

def schema(db,alias,table,columns):
    row=db.execute('SELECT type FROM '+alias+'.sqlite_master WHERE name=?',(table,)).fetchone()
    need(row==('table',),'database_table_required')
    actual={r[1] for r in db.execute('PRAGMA '+alias+'.table_info('+table+')')}
    need(set(columns)<=actual,'unsupported_database_schema')

def attach(db,watch,path,alias):
    path=watch.file(path)
    for suffix in ('-wal','-shm','-journal'):
        need(not Path(str(path)+suffix).exists(),'database_sidecar_present')
    with path.open('rb') as f:
        need(fp(os.fstat(f.fileno()))==watch.files[path],'source_changed')
        header=f.read(100)
    need(header[:16]==b'SQLite format 3\x00' and len(header)==100 and header[18:20]==b'\x01\x01','closed_rollback_database_required')
    watch.databases.append(path)
    # No immutable shortcut: actual source identity rechecked before/after reads.
    db.execute('ATTACH DATABASE ? AS '+alias,(path.as_uri()+'?mode=ro',))
    schema(db,alias,'metadata',('name','value'))

def lab_file(objects,name,prefix,watch,expected=None):
    need(isinstance(name,str) and re.fullmatch(re.escape(prefix)+r'-[0-9a-f]{32}\.sqlite',name),'owned_filename_required')
    return watch.file(objects/name,expected)

def ref(objects,record,prefix,watch):
    need(isinstance(record,dict) and set(record)>={'name','fingerprint'},'saved_reference_shape')
    need(isinstance(record['fingerprint'],list) and len(record['fingerprint'])==5,'fingerprint_shape')
    return lab_file(objects,record['name'],prefix,watch,record['fingerprint'])

def load_metadata(audit_dir,watch):
    root=safe(audit_dir)
    build_raw=watch.read(root/'build.config')
    build=a.config(build_raw,a.BUILD)
    need(build.get('build-uid')==['wow'] and build.get('build-name')==['WOW-70391patch12.1.5_Retail'],'pinned_build_identity')
    need(len(build.get('patch',[]))==len(build.get('patch-size',[]))==1,'patch_binding_shape')
    if (root/'manifest.pa').exists() or (root/'manifest.pa').is_symlink():
        raw=watch.read(root/'manifest.pa')
    else:
        # Plain text shards permit exact preservation via the connected GitHub
        # file API. Offline assembly only; these are public metadata, not code.
        encoded=b''.join(watch.read(root/('manifest.pa.base64.part'+str(i)),1024**2) for i in range(3))
        try:raw=base64.b64decode(encoded,validate=True)
        except binascii.Error:raise BindingError('pinned_manifest_encoding') from None
    need(len(raw)==int(build['patch-size'][0]),'manifest_size_binding')
    options,report=a.manifest(raw,build['patch'][0])
    download=build.get('download',[])
    need(len(download)==2,'pinned_download_binding_shape')
    for key in download:a.key(key)
    return options,report,{'build_config':a.BUILD,'cdn_config':a.CDN,'version':a.VERSION,'product':'wow','region':'eu',
                           'download_ckey':download[0],'download_ekey':download[1]}

def validate_bindings(bindings,expected):
    # Require the entire saved binding dictionaries to agree, including fields
    # not interpreted here. Only CDN identity may differ from audit metadata;
    # build + both download keys still bind the exact content catalogue.
    need(len(bindings)==4 and all(isinstance(obj,dict) for obj in bindings),'target_binding_conflict')
    need(all(obj==bindings[0] for obj in bindings),'target_binding_conflict')
    obj=bindings[0]
    need(set(expected)>={'product','region','version','build_config','cdn_config','download_ckey','download_ekey'},'pinned_download_binding_shape')
    need(expected['cdn_config']==a.CDN,'pinned_cdn_identity_conflict')
    need(all(obj.get(k)==v for k,v in expected.items() if k!='cdn_config'),'target_binding_conflict')
    need(obj.get('cdn_config') in OFFLINE_CDN_IDENTITIES,'target_binding_conflict')
    return {**expected,'cdn_config':obj['cdn_config']}


def bind(lab_root,audit_dir,*,time_limit=120,max_private=256,cancel=lambda:False):
    """Metadata-only plan. Exact prior proof is still subject to targeted re-read.

    Prior candidates were projected against target EKeys, NOT an exhaustive
    inventory of old patch bases. No full proof -> UNKNOWN, never corrupt/missing.
    """
    need(type(max_private)is int and 1<=max_private<=256,'private_plan_limit')
    watch=Watch();lab=safe(lab_root);objects=safe(lab/'objects')
    marker=json_object(watch.read(lab/'LAB-ONLY.json'))
    need(marker.get('format')=='wow-repair-lab-1' and marker.get('real_game_installation')is False and re.fullmatch('[0-9a-f]{32}',str(marker.get('id',''))),'lab_marker_invalid')
    state=json_object(watch.read(objects/'downloader-ui-session.json'))
    need(state.get('format')=='queue-downloader-ui-1','session_format')
    record=state.get('local_review')
    need(isinstance(record,dict) and record.get('format')=='offline-local-review-1','saved_local_review_required_no_migration')
    plan=ref(objects,record.get('plan_file'),'content-plan',watch)
    queue=ref(objects,record.get('queue_file'),'acquisition-queue',watch)
    need(plan.name==state.get('plan') and queue.name==state.get('queue'),'session_reference_conflict')
    inv=ref(objects,record.get('local_inventory'),'local-casc-inventory',watch)
    ev=ref(objects,record.get('latest_local'),'local-casc-evidence',watch)
    need(record.get('merged_checkpoint')==ev.name,'unmerged_local_checkpoint')
    options,maudit,expected=load_metadata(audit_dir,watch)
    start=time.monotonic()
    db=sqlite3.connect(':memory:',uri=True)
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA temp_store=MEMORY')
    db.set_progress_handler(lambda:int(cancel() or time.monotonic()-start>time_limit),10000)
    try:
        for alias,path in [('p',plan),('q',queue),('i',inv),('e',ev)]:attach(db,watch,path,alias)
        schema(db,'p','plan',('ekey','ckey','decoded_size','encoded_size','mapping_state','transfer_supported'))
        schema(db,'i','candidates',('id','ekey','archive_id','payload_offset','encoded_size','ckey','decoded_size'))
        schema(db,'i','archives',('archive_id','name','size','ambiguous'))
        schema(db,'e','evidence',('ordinal','ekey','kind','state','bytes_read','decoded_content_verified','encoded_object_verified','source_path'))
        bindings=[metadata(db,al,'target_binding') for al in ('p','q','i','e')]
        expected=validate_bindings(bindings,expected)
        pid=metadata(db,'p','plan_id')
        need(isinstance(pid,str) and re.fullmatch('[0-9a-f]{32}',pid) and record.get('plan_id')==pid,'plan_id_conflict')
        need(all(metadata(db,al,'source_plan_id')==pid for al in ('i','e','q')),'plan_id_conflict')
        sid=metadata(db,'i','source_snapshot_id')
        need(isinstance(sid,str) and metadata(db,'e','source_snapshot_id')==sid,'snapshot_id_conflict')
        summary=metadata(db,'e','local_verification_summary')
        need(summary.get('candidate_rows_pending')==0 and summary.get('all_discovered_candidates_processed')is True,'incomplete_saved_review')
        snapshot=metadata(db,'i','local_storage_snapshot');folder=watch.snapshot(snapshot)
        need(not (lab==folder or lab in folder.parents or folder in lab.parents),'lab_storage_overlap')
        # Small, transient table only; no index added to any source DB. Scan saved
        # catalogue metadata once instead of millions of full-table point queries.
        db.execute('CREATE TEMP TABLE wanted(ckey BLOB PRIMARY KEY,decoded_size INTEGER NOT NULL) WITHOUT ROWID')
        targets={}
        for o in options:
            need(o.target_ckey not in targets or targets[o.target_ckey]==o.target_size,'target_size_conflict')
            targets[o.target_ckey]=o.target_size
        db.executemany('INSERT INTO wanted VALUES (?,?)',[(bytes.fromhex(k),v) for k,v in targets.items()])
        selected={r[0] for r in db.execute('''SELECT DISTINCT p.ckey FROM p.plan p CROSS JOIN wanted w
             ON p.ckey=w.ckey AND p.decoded_size=w.decoded_size
             WHERE p.mapping_state='mapped' AND p.transfer_supported=1''')}
        # Existing EKey index is required; do not create one or O(N) rescan for
        # each key when reading a legacy/unsupported inventory.
        indexes=[]
        for row in db.execute('PRAGMA i.index_list(candidates)'):
            name=row[1]
            cols=[r[2] for r in db.execute('PRAGMA i.index_info('+"'"+name.replace("'","''")+"'"+')')]
            if cols and cols[0]=='ekey':indexes.append(name)
        need(indexes,'existing_source_ekey_index_required')
        counts=Counter();rows=[];proof_sources=set();queried={};source_candidates=0
        for o in options:
            if cancel():raise BindingError('cancelled')
            need(time.monotonic()-start<=time_limit,'metadata_time_limit')
            if bytes.fromhex(o.target_ckey) not in selected:
                counts['target_not_bound_to_saved_catalogue']+=1;continue
            ek=bytes.fromhex(o.source_ekey)
            if ek not in queried:
                found=db.execute('''SELECT c.id,c.ekey,c.archive_id,c.payload_offset,c.encoded_size,c.ckey,c.decoded_size,
                    a.name,a.size,a.ambiguous,e.ekey,e.kind,e.state,e.bytes_read,e.decoded_content_verified,
                    e.encoded_object_verified,e.source_path FROM i.candidates c
                    LEFT JOIN i.archives a ON a.archive_id=c.archive_id
                    LEFT JOIN e.evidence e ON e.ordinal=c.id WHERE c.ekey=? LIMIT 65''',(ek,)).fetchall()
                need(len(found)<=64,'source_alias_limit');queried[ek]=found
            found=queried[ek]
            if not found:
                counts['source_outside_saved_target_candidate_inventory']+=1;continue
            matching=[]
            for r in found:
                cid,cek,aid,offset,es,ck,ds,name,archive_size,ambiguous,eek,kind,state,n,cv,evv,path=r
                if ds!=o.source_size:continue
                # Never turn a bare EKey match or an alias marker into proof.
                if not (eek==cek==ek and kind=='casc_span' and state=='encoded_and_decoded_content_verified' and cv==evv==1 and n==es):continue
                need(isinstance(ck,bytes) and len(ck)==16 and type(es)is int and es>0,'proof_content_shape')
                need(type(offset)is int and offset>=0 and type(aid)is int and aid>=0 and ambiguous==0
                     and isinstance(name,str) and re.fullmatch(r'data\.[0-9]{3,}',name)
                     and name in snapshot['files'] and type(archive_size)is int
                     and archive_size==snapshot['files'][name][2] and offset+es<=archive_size,'proof_coordinates_conflict')
                need(path==str(folder/name),'proof_source_path_conflict')
                matching.append((es,offset,cid,ck,name))
            if not matching:
                status='source_size_conflict_with_saved_candidates' if all(r[6]!=o.source_size for r in found) else 'source_candidates_without_full_matching_proof'
                counts[status]+=1;continue
            es,offset,cid,ck,name=min(matching)
            counts['prior_full_source_proof_bound_reverification_required']+=1;proof_sources.add(o.source_ekey)
            bounded=(es<=a.MAX_OUTPUT and o.source_size<=a.MAX_OUTPUT and o.target_size<=a.MAX_OUTPUT and o.patch_size<=a.MAX_PATCH)
            if bounded:
                rows.append({**asdict(o),'source_ckey':ck.hex(),'source_encoded_size':es,
                             'source_path':str(folder/name),'source_offset':offset,'source_candidate_id':cid,
                             'source_stat_fingerprint':snapshot['files'][name],
                             'state':'prior_full_proof_bound_not_freshly_reverified',
                             'apply_authorized':False,'patch_order_policy_proven':False})
        need(sum(counts.values())==len(options),'option_count_reconciliation')
        watch.check()
        rows.sort(key=lambda r:(r['source_encoded_size']+r['patch_size'],r['target_ckey'],r['patch_key']))
        public={'schema':1,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'status':'offline_prior_source_proof_binding_complete',
                'target':expected,'audit_metadata_cdn_config':a.CDN,
                'cdn_binding_policy':'offline_only_two_pinned_identities_same_build_and_download_manifest',
                'cdn_routes_used':False,'cdn_route_equivalence_claimed':False,'manifest_blocks_verified':maudit['blocks'],'manifest_patch_options':len(options),
                'options_by_state':dict(sorted(counts.items())),'unique_source_ekeys_with_bound_prior_full_proof':len(proof_sources),
                'bounded_options_for_future_targeted_reverification':len(rows),'private_options_emitted':min(len(rows),max_private),
                'source_candidates_were_target_projected_not_all_old_assets':True,
                'source_inventory_scope':'saved_local_casc_candidates_only',
                'legacy_cache_or_decoded_staging_sources_evaluated':False,
                'source_fingerprints_checked':True,'consistency_model':'saved_file_set_and_stat_fingerprints_not_OS_snapshot',
                'archive_payload_bytes_read':0,'network_requests':0,'lab_files_modified':False,'game_files_modified':False,
                'saved_catalogue_metadata_scanned_once':True,'profile_selection_applied':False,
                'fresh_source_content_verified':False,'patch_applied':False,'patch_order_policy_proven':False,
                'unknown_is_not_missing_or_corrupt':True,'required_network_download_bytes':None,'installation_ready':False,
                'elapsed_seconds':round(time.monotonic()-start,3)}
        private={'format':'patch-source-binding-private-1','target':expected,'plan_id':pid,'snapshot_id':sid,
                 'source_provenance_is_private':True,'apply_authorized':False,
                 'watched_files':[{'path':str(p),'fingerprint':v} for p,v in watch.files.items()],
                 'local_storage_snapshot':snapshot,'options':rows[:max_private],
                 'requirements':['Recheck exact source bytes EKey + chunk hashes + decoded CKey before application.',
                                 'Bind patch bytes to verified index route; ordinal/chaining policy unresolved.',
                                 'Verify final target CKey in separate staging; never write game or Lab.']}
        return public,private
    except sqlite3.OperationalError as e:
        raise BindingError('cancelled_or_metadata_query_rejected') from None
    finally:
        db.close()
