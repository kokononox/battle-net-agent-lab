"""Offline logical old/new Download-manifest delta. NOT an installation deficit.

No network or Agent; never re-verify all asset payloads. Read only installed
identity, cached target DL and, if needed, exact old DL from a checksum-verified
index reference with full metadata EKey/chunk/CKey proof. Outputs in a new owned
planning workspace, not in the game or the review session/evidence databases.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import uuid
import acquisition_runner as runner
import cache_evidence as cache
import decoded_payload
import download_inventory as download
import installed_metadata as installed
import local_casc as local
import plan_storage as store
import repair_core as core

MAX_META=256*1024**2
MAX_ARCHIVE_META_READ=512*1024**2


def cached_manifest(lab,ckey,expected_size=None,cancel=None):
    cancel=cancel or threading.Event()
    matches=[]
    for path in (lab.root/'objects').glob(ckey+'-*.decoded'):
        core.check(cancel);path=core.regular(path)
        if path.stat().st_size>MAX_META:raise core.RepairError('cached_download_manifest_size_limit')
        if expected_size is not None and path.stat().st_size!=expected_size:continue
        matches.append(path)
        if len(matches)>1:raise core.RepairError('cached_download_manifest_ambiguous')
    if not matches:return None
    proof=core.digest(matches[0],cancel)
    if proof['md5']!=ckey:raise core.RepairError('cached_download_manifest_ckey_mismatch')
    return matches[0]


def index_bucket(ekey):
    # CASC normal entries: XOR every nibble of the 9-byte EKey prefix.
    # https://wowdev.wiki/CASC#.IDX_Journals
    if not isinstance(ekey,bytes) or len(ekey) not in (9,16):raise core.RepairError('planner_invalid_index_lookup_key')
    value=0
    for b in ekey[:9]:value^=b
    return (value^(value>>4))&15


def extract_installed_download(workspace,identity,descriptor,cancel=None,notify=lambda _:None):
    cancel=cancel or threading.Event();identity.check();snapshot=local._snapshot(identity.storage)
    all_indexes=[n for n in snapshot['files'] if n.lower().endswith('.idx')]
    if len(all_indexes)>1024 or sum(snapshot['files'][n][2] for n in all_indexes)>local.MAX_INDEX_TOTAL:
        raise core.RepairError('planner_local_index_metadata_limit')
    archives={}
    for name in snapshot['files']:
        m=local.ARCH.fullmatch(name)
        if m:archives.setdefault(int(m[1]),[]).append(name)
    candidates=set();verified=entries=0
    ek=bytes.fromhex(descriptor['ekey']);es=descriptor['encoded_size'];bucket=index_bucket(ek)
    indexes=[n for n in all_indexes if local.IDX.fullmatch(n) and int(local.IDX.fullmatch(n)[1],16)==bucket]
    for j,name in enumerate(indexes):
        core.check(cancel);notify({'stage':'old_download_index_lookup','indexes_checked':j,'index_total':len(indexes),'network_requests':0})
        raw=local._read_index(core.regular(identity.storage/name),snapshot['files'][name],cancel)
        proof=local.index_proof(raw,name,cancel)
        if not proof['checksum_verified']:continue
        verified+=1;entries+=proof['entries']
        if entries>local.MAX_ENTRIES:raise core.RepairError('planner_local_index_entry_limit')
        for i in range(proof['entries']):
            if i%4096==0:core.check(cancel)
            e=raw[40+i*18:58+i*18]
            if e[:9]!=ek[:9]:continue
            packed=int.from_bytes(e[9:14],'big');aid=packed>>30;offset=packed&((1<<30)-1);span=int.from_bytes(e[14:],'little')
            names=archives.get(aid,[])
            if len(names)!=1 or span not in (es,es+30):continue
            if offset+span>snapshot['files'][names[0]][2]:continue
            candidates.add((names[0],offset+(30 if span==es+30 else 0)))
            if len(candidates)>64:raise core.RepairError('planner_download_candidate_limit')
    local._stable(snapshot);identity.check()
    if not candidates:raise core.RepairError('installed_download_manifest_not_found_locally')
    reserved=read=0
    for name,offset in sorted(candidates):
        core.check(cancel);identity.check();local._stable(snapshot)
        if reserved+es>MAX_ARCHIVE_META_READ:raise core.RepairError('planner_archive_metadata_read_budget')
        reserved+=es
        source=core.regular(identity.storage/name);fp=core.fingerprint(source.stat())
        temp=core.safe(workspace.root/'objects'/('old-download-'+uuid.uuid4().hex+'.tmp'))
        try:
            with source.open('rb') as src,temp.open('xb') as sink:
                if core.fingerprint(os.fstat(src.fileno()))!=fp:raise core.RepairError('planner_metadata_source_changed')
                slice=cache.Slice(src,offset,es)
                class Counted:
                    def read(self,n):
                        nonlocal read
                        b=slice.read(n);read+=len(b);return b
                proof=decoded_payload.extract(Counted(),es,descriptor['decoded_size'],bytes.fromhex(descriptor['ckey']),ek,cancel,sink)
                sink.flush();os.fsync(sink.fileno())
                if core.fingerprint(os.fstat(src.fileno()))!=fp:raise core.RepairError('planner_metadata_source_changed')
            if not proof['encoded_integrity_verified'] or not proof['decoded_ckey_verified']:raise core.RepairError('planner_download_full_metadata_proof_missing')
            local._stable(snapshot);identity.check()
            final=workspace.root/'objects'/(descriptor['ckey']+'-'+str(descriptor['decoded_size'])+'.decoded')
            os.replace(temp,final);core.sync_dir(final.parent)
            return final,{'old_manifest_source':'verified_local_archive_metadata','archive_metadata_bytes_read':read,
                          'checksum_verified_local_indexes':verified,'selected_index_bucket':bucket,'candidate_metadata_locations':len(candidates)},snapshot
        except decoded_payload.PayloadError as e:
            if e.reason=='cancelled':raise core.Cancelled('cancelled') from None
            # A failed candidate is not a corruption verdict or proof of absence.
            local._stable(snapshot);identity.check()
        finally:
            if temp.exists():core.regular(temp).unlink()
    raise core.RepairError('installed_download_manifest_candidates_not_fully_proven')


def inventory(workspace,source,ckey,binding,cancel=None,notify=lambda _:None):
    cancel=cancel or threading.Event();core.check(cancel);source=core.regular(source)
    if source.stat().st_size>MAX_META:raise core.RepairError('planner_manifest_size_limit')
    fp=core.fingerprint(source.stat());digest=core.digest(source,cancel)
    if digest['md5']!=ckey:raise core.RepairError('planner_manifest_ckey_mismatch')
    if shutil.disk_usage(workspace.root).free<4*digest['size']+64*1024**2:raise core.RepairError('planner_inventory_space')
    with store.Writer(workspace,'metadata-download',cancel) as out:
        out.watch(source,fp);db=out.db
        db.executescript('''CREATE TABLE entries(ordinal INTEGER PRIMARY KEY,ekey BLOB NOT NULL,encoded_size INTEGER NOT NULL,
            raw_priority INTEGER NOT NULL,priority_minus_base INTEGER NOT NULL,checksum BLOB,flags BLOB NOT NULL);
            CREATE TABLE tags(ordinal INTEGER PRIMARY KEY,name TEXT NOT NULL,kind INTEGER NOT NULL,bitmap BLOB NOT NULL,
                member_records INTEGER NOT NULL,nonzero_padding INTEGER NOT NULL);''')
        with source.open('rb') as f:
            if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('planner_manifest_changed')
            summary=download._parse(f,db,cancel,lambda s:notify({'stage':'manifest_metadata_parse','message':s,'network_requests':0}))
            if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('planner_manifest_changed')
        out.metadata('target_binding',binding);out.metadata('inventory_summary',summary)
        out.metadata('manifest_ckey',ckey);out.metadata('source_sha256',digest['sha256'])
    return out.path


def compare(workspace,old_path,target_path,cancel=None):
    cancel=cancel or threading.Event();core.check(cancel)
    with store.input_db(workspace,old_path) as (_,old_binding),store.input_db(workspace,target_path) as (_,target_binding),store.Writer(workspace,'logical-delta',cancel) as out:
        out.watch(old_path);out.watch(target_path);db=out.db
        db.execute('ATTACH DATABASE ? AS old',(old_path.as_uri()+'?mode=ro',));db.execute('ATTACH DATABASE ? AS target',(target_path.as_uri()+'?mode=ro',))
        db.executescript('CREATE TEMP TABLE old_keys AS SELECT * FROM old.objects; CREATE UNIQUE INDEX old_keys_key ON old_keys(ekey); CREATE TEMP TABLE target_keys AS SELECT * FROM target.objects; CREATE UNIQUE INDEX target_keys_key ON target_keys(ekey);')
        conflict=db.execute('SELECT 1 FROM old_keys o JOIN target_keys n USING(ekey) WHERE o.encoded_size!=n.encoded_size LIMIT 1').fetchone()
        if conflict:raise core.RepairError('metadata_shared_ekey_size_conflict')
        db.executescript('''CREATE TABLE delta(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL,kind TEXT NOT NULL);
            INSERT INTO delta SELECT n.ekey,n.encoded_size,CASE WHEN o.ekey IS NULL THEN 'added' ELSE 'common' END
                FROM target_keys n LEFT JOIN old_keys o USING(ekey);
            INSERT INTO delta SELECT o.ekey,o.encoded_size,'removed' FROM old_keys o LEFT JOIN target_keys n USING(ekey) WHERE n.ekey IS NULL;''')
        counts={kind:n for kind,n in db.execute('SELECT kind,COUNT(*) FROM delta GROUP BY kind')}
        old_count=db.execute('SELECT COUNT(*) FROM old_keys').fetchone()[0];new_count=db.execute('SELECT COUNT(*) FROM target_keys').fetchone()[0]
        common=counts.get('common',0);added=counts.get('added',0);removed=counts.get('removed',0)
        # Independent set-operator check, not the classification join above.
        check_added=db.execute('SELECT COUNT(*) FROM (SELECT ekey FROM target_keys EXCEPT SELECT ekey FROM old_keys)').fetchone()[0]
        check_removed=db.execute('SELECT COUNT(*) FROM (SELECT ekey FROM old_keys EXCEPT SELECT ekey FROM target_keys)').fetchone()[0]
        if (old_count!=common+removed or new_count!=common+added or added!=check_added or removed!=check_removed):raise core.RepairError('metadata_delta_reconciliation_failed')
        result={'old_catalogue_objects':old_count,'target_catalogue_objects':new_count,'common_encoded_keys':common,
            'added_encoded_keys':added,'removed_encoded_keys':removed,
            'added_full_encoded_representation_bytes':db.execute("SELECT COALESCE(SUM(encoded_size),0) FROM delta WHERE kind='added'").fetchone()[0],
            'scope':'all_Download_records_all_tags;logical_encoding_difference_only',
            'independent_set_reconciliation_passed':True,'local_possession_inferred_from_old_catalogue':False,
            'patch_delta_savings_applied':False,'required_network_download_bytes':None,'installation_ready':False}
        out.metadata('target_binding',target_binding);out.metadata('old_binding',old_binding);out.metadata('logical_delta_summary',result)
    return result,out.path


def plan(lab,plan_path,storage,cancel=None,notify=lambda _:None,scope_analyzer=None,publication_check=None):
    """A separate new workspace; never mutate the review's state, queues or proofs.

    Cached target is pinned metadata, NOT asserted to be latest official online.
    All-tag difference is not a vendor install policy or required update size.
    """
    cancel=cancel or threading.Event();core.check(cancel);runner.external_workspace(lab.root);plan_path=store.owned(lab,plan_path)
    storage=core.safe(storage)
    if storage.name.lower()!='data' or storage.parent.name.lower()!='data':raise core.RepairError('planner_expected_game_Data_data')
    identity=installed.read(storage.parent.parent,cancel)
    if identity.storage!=storage:raise core.RepairError('planner_installed_storage_conflict')
    if identity.root==lab.root or identity.root in lab.root.parents or lab.root in identity.root.parents:
        raise core.RepairError('planner_lab_must_be_separate_from_game')
    plan_fp=core.fingerprint(plan_path.stat())
    with store.input_db(lab,plan_path) as (_,binding):binding=dict(binding)
    ck=binding.get('download_ckey')
    if not isinstance(ck,str):raise core.RepairError('target_plan_download_identity_missing')
    import target_metadata as meta
    meta.key(ck)
    target_source=cached_manifest(lab,ck,cancel=cancel)
    if target_source is None:raise core.RepairError('target_download_manifest_missing_from_cache_no_network')
    target_fp=core.fingerprint(target_source.stat());descriptor=installed.download_descriptor(identity.build)
    old_source=cached_manifest(lab,descriptor['ckey'],descriptor['decoded_size'],cancel)
    old_snapshot=None
    space_needed=max(2*1024**3,12*(descriptor['decoded_size']+target_source.stat().st_size)+256*1024**2)
    if shutil.disk_usage(lab.root).free<space_needed:raise core.RepairError('metadata_planner_space_preflight_failed')
    workspace=core.Lab.create(core.safe(lab.root/('metadata-planning-'+uuid.uuid4().hex)))
    old_details={'old_manifest_source':'verified_decoded_metadata_cache','archive_metadata_bytes_read':0}
    if old_source is None:
        old_source,old_details,old_snapshot=extract_installed_download(workspace,identity,descriptor,cancel,notify)
    old_fp=core.fingerprint(old_source.stat())
    old_binding={'product':'wow','region':identity.row['branch'] or 'unknown','version':identity.version,
                 'build_config':identity.row['buildkey'],'cdn_config':identity.row['cdnkey'] or 'unknown'}
    old_db=inventory(workspace,old_source,descriptor['ckey'],old_binding,cancel,notify)
    new_db=inventory(workspace,target_source,ck,binding,cancel,notify)
    delta,delta_path=compare(workspace,old_db,new_db,cancel)
    scope = scope_analyzer(workspace,old_db,new_db,identity,cancel,notify) if scope_analyzer is not None else None
    identity.check()
    if old_snapshot is not None:local._stable(old_snapshot)
    for path,fp in ((plan_path,plan_fp),(target_source,target_fp),(old_source,old_fp)):
        if core.fingerprint(core.regular(path).stat())!=fp:raise core.RepairError('metadata_planner_input_changed')
    core.check(cancel)
    report={'tool':'WoW Offline Metadata Delta Preview','status':'logical_catalogue_delta_complete',
            'installed_identity':identity.public(),'pinned_target_version':binding['version'],
            'pinned_target_is_latest_online_proven':False,'installed_build_matches_pinned_target':identity.row['buildkey']==binding['build_config'],
            'old_manifest_metadata':old_details,'logical_catalogue_delta':delta,'installed_profile_filter_applied':False,
            'full_asset_verification_performed':False,'non_metadata_game_payload_bytes_read':0,
            'network_requests':0,'Agent_started':False,'game_files_modified':False,'review_state_or_queue_modified':False,
            'required_network_download_bytes':None,'installation_ready':False}
    if scope is not None:
        report.update(tool='WoW Offline Update Scope Preview',status='profile_and_local_proof_scope_complete',update_scope=scope,installed_profile_filter_applied=True)
    with lab.lock():
        identity.check()
        for path,fp in ((plan_path,plan_fp),(target_source,target_fp),(old_source,old_fp)):
            if core.fingerprint(core.regular(path).stat())!=fp:raise core.RepairError('metadata_planner_input_changed')
        if old_snapshot is not None:local._stable(old_snapshot)
        if publication_check is not None:publication_check()
        core.atomic_json(core.safe(lab.root/'objects'/((('Retail-Update-Scope-to-share-' if scope is not None else 'Retail-Metadata-Plan-to-share-'))+uuid.uuid4().hex+'.json')),report)
    return report


def plan_from_queue(lab,plan_path,queue_path,cancel=None,notify=lambda _:None):
    import reuse_coordinator as reuse
    reuse.checked_queue(lab,plan_path,queue_path)
    with store.input_db(lab,queue_path) as (q,_):
        snapshots=local._meta(q,'source_snapshot')['local_snapshots']
        if len(snapshots)!=1:raise core.RepairError('metadata_planner_requires_one_recorded_game_storage')
        storage=core.safe(snapshots[0]['directory'])
    return plan(lab,plan_path,storage,cancel,notify)
