"""Read-only saved-snapshot/profile/Download diagnostic. NOT an updater.

No network, archive-content reads, scan restart, Lab/game writes or DB rebuild.
Reads TWO permitted game metadata files, existing saved Lab metadata, and ONLY
its exact CKey/size-named decoded Download cache (<=256 MiB) if present.
Projects record bits, NOT unique objects, vendor install closure or network size.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,stat,time,uuid
import installed_profile_probe as p
import source_binding as b
import patch_audit as a
VERSION='saved-scope-review-1'
MAX_MANIFEST=256*1024**2
MAX_RECORDS=10_000_000
MAX_TAGS=4096
MAX_BITMAP_STATE=48*1024**2
TIME_LIMIT=300
DIMENSIONS=(p.PLATFORMS,p.ARCHITECTURES,p.LOCALES,p.REGIONS)
PHASES={'start','read_installed_identity','bind_saved_snapshot','bind_selected_storage',
        'locate_saved_download','validate_download_records','project_download_tags',
        'final_input_recheck','prepare_report_output','write_pending_report',
        'publish_report_noreplace','postpublication_recheck','complete'}
class Progress:
    def __init__(self):self.stage='start'
    def mark(self,stage):b.need(stage in PHASES,'scope_phase_invalid');self.stage=stage

def public_error(ex,stage='start'):
    q={'status':'stopped_safely','scope_review_version':VERSION,
       'stage':stage if stage in PHASES else 'start','error_type':type(ex).__name__,
       'installation_ready':False,'unknown_is_not_missing_or_corrupt':True}
    if isinstance(ex,(b.BindingError,p.ProbeError,a.AuditError)) and re.fullmatch('[a-z0-9_]{1,100}',str(ex)):q['code']=str(ex)
    if isinstance(ex,OSError):
        for k in ('errno','winerror'):
            if type(getattr(ex,k,None))is int:q[k]=getattr(ex,k)
    return q

class ManifestReader:
    def __init__(self,f,size,check):self.f=f;self.size=size;self.used=0;self.md5=hashlib.md5();self.sha=hashlib.sha256();self.check=check
    def read(self,n):
        b.need(type(n)is int and 0<=n<=MAX_MANIFEST and self.used+n<=self.size,'download_manifest_declared_bounds')
        raw=self.f.read(n);b.need(len(raw)==n,'download_manifest_truncated')
        self.used+=n;self.md5.update(raw);self.sha.update(raw);return raw

def parse_manifest(reader,profile,*,progress=lambda _:None):
    """Single sequential metadata pass, bounded bitmap state, no object DB.

    Optional high-bit 0x4000 is normalized for this DIAGNOSTIC only. Unknown
    dimension values/kinds fail closed; non-dimension tags are NOT exclusions.
    No unique-object, duplicate-size, priority/checksum algorithm proof is made.
    """
    r=reader;h=r.read(11)
    b.need(h[:2]==b'DL' and h[2] in (1,2,3) and h[3]==16,'unsupported_download_header')
    version,checks=h[2],h[4];b.need(checks in (0,1),'unsupported_download_checksum_marker')
    n,nt=int.from_bytes(h[5:9],'big'),int.from_bytes(h[9:11],'big')
    b.need(1<=n<=MAX_RECORDS and nt<=MAX_TAGS,'download_manifest_count_limit')
    flags=r.read(1)[0] if version>=2 else 0;b.need(flags<=4,'unsupported_download_flag_size')
    extra=r.read(4) if version>=3 else b'\0'*4
    b.need(not any(extra[1:]),'unsupported_download_reserved_bytes')
    es=22+4*checks+flags;width=(n+7)//8;padding=width*8-n
    b.need(n*es+nt*(3+width)<=r.size-r.used,'download_manifest_declared_bounds')
    b.need(width*24<=MAX_BITMAP_STATE,'download_bitmap_memory_limit')
    progress('validate_download_records')
    for ordinal in range(n):
        if ordinal%4096==0:r.check()
        entry=r.read(es);b.need(entry[:16]!=bytes(16),'zero_download_ekey_unsupported')
    valid=((1<<n)-1)<<padding;union=[0]*4;chosen=[0]*4;found=[set() for _ in range(4)];seen=set()
    requested=({profile['platform']},{profile['architecture']},set(profile['locales']),{profile['region']})
    optional=0;non_dimension=0;progress('project_download_tags')
    for ordinal in range(nt):
        r.check();name=bytearray()
        while True:
            c=r.read(1)
            if c==b'\0':break
            name+=c;b.need(len(name)<=256,'download_tag_name_limit')
        try:text=name.decode('utf-8')
        except UnicodeError:raise b.BindingError('download_tag_encoding') from None
        b.need(text and all(ord(c)>=32 and ord(c)!=127 for c in text),'download_tag_name_invalid')
        kind=int.from_bytes(r.read(2),'big');base=kind&~0x4000
        b.need((base,text) not in seen,'duplicate_or_optional_alias_download_tag');seen.add((base,text))
        optional+=bool(kind&0x4000);mask=int.from_bytes(r.read(width),'big')
        b.need(not mask&((1<<padding)-1),'download_bitmap_nonzero_padding')
        expected=next((i+1 for i,values in enumerate(DIMENSIONS) if text in values),None)
        if expected is not None:b.need(base==expected,'download_known_tag_kind_conflict')
        if base in (1,2,3,4):
            b.need(text in DIMENSIONS[base-1],'download_unknown_dimension_tag_no_guess')
            union[base-1]|=mask
            if text in requested[base-1]:chosen[base-1]|=mask;found[base-1].add(text)
        else:
            # Unknown kind semantics are NOT guessed as optional categories.
            b.need(base==0,'download_unknown_tag_kind_no_guess');non_dimension+=1
    b.need(r.used==r.size,'download_manifest_trailing_bytes')
    b.need(all(found[i]==requested[i] for i in range(4)),'download_requested_tag_absent_no_fallback')
    selected=valid
    for u,c in zip(union,chosen):selected &= c | (valid ^ u)
    r.check()
    return {'format_version':version,'manifest_records':n,'manifest_tags':nt,
        'diagnostic_selected_records':selected.bit_count(),'diagnostic_unselected_records':n-selected.bit_count(),
        'selection_unit':'record_bits_NOT_unique_encoded_objects',
        'policy':'matching_or_unclassified_per_dimension;OR_locales;AND_dimensions',
        'optional_kind_bit_normalized_for_diagnostic_only':True,'tags_with_optional_kind_bit':optional,
        'non_dimension_tags_not_excluded':non_dimension,'requested_dimension_tags_all_present':True,
        'record_checksums_present':bool(checks),'record_checksum_algorithm_validated':False,
        'unique_objects_or_duplicate_size_consistency_computed':False,'vendor_install_policy_proven':False,
        'selected_ekeys_exported':False,'selected_encoded_bytes_computed':False}

def reconstruct(private):
    w=b.Watch()
    for row in private['watched_files']:w.file(row['path'],row['fingerprint'])
    w.databases=[Path(q) for q in private['closed_databases']]
    w.snapshot(private['local_storage_snapshot']);w.check();return w

def review(lab,audit,game,*,cancel=lambda:False,progress=lambda _:None):
    start=time.monotonic()
    def checked():b.need(not cancel() and time.monotonic()-start<=TIME_LIMIT,'scope_cancelled_or_time_limit')
    checked();lab=b.safe(lab);audit=b.safe(audit);game=b.safe(game)
    b.need(not(lab==game or lab in game.parents or game in lab.parents),'scope_lab_game_overlap')
    progress('read_installed_identity');installed,ip=p.read(game,cancel=cancel)
    b.need(installed['profile'] is not None,'installed_profile_unresolved_no_guess')
    progress('bind_saved_snapshot');_,saved=b.bind(lab,audit,max_private=1,cancel=cancel,time_limit=120)
    private={**saved,'closed_databases':[r['path'] for r in saved['watched_files'] if Path(r['path']).suffix=='.sqlite'],
             'protected_roots':[str(lab),str(audit),str(game)]}
    w=reconstruct(private)
    for path,fp in ip['watch'].files.items():w.file(path,fp)
    progress('bind_selected_storage');storage=b.safe(game/'Data'/'data')
    b.need(storage.is_dir() and storage==b.safe(saved['local_storage_snapshot']['directory']),'selected_game_not_saved_snapshot_storage')
    checked();w.check()
    progress('locate_saved_download');config=a.config(w.read(audit/'build.config'),a.BUILD)
    sizes=config.get('download-size',[]);keys=config.get('download',[])
    b.need(len(sizes)==2 and all(re.fullmatch('[0-9]{1,12}',s) for s in sizes),'pinned_download_size_shape')
    size=int(sizes[0]);b.need(11<=size<=MAX_MANIFEST and keys==[saved['target']['download_ckey'],saved['target']['download_ekey']],'pinned_download_spec_conflict')
    manifest=lab/'objects'/(keys[0]+'-'+str(size)+'.decoded')
    report={'format':'readonly-saved-scope-review-1','scope_review_version':VERSION,
        'status':'bound_download_metadata_unavailable','installed_identity':installed['installed_identity'],
        'profile':installed['profile'],'profile_source':installed['profile_source'],
        'pinned_target':saved['target'],'selected_game_matches_saved_snapshot_storage':True,
        'saved_snapshot_stat_fingerprints_rechecked':True,'bound_to_existing_Lab_snapshot':True,
        'scope_binding_digest':hashlib.sha256(json.dumps({'target':saved['target'],'plan_id':saved['plan_id'],
             'snapshot_id':saved['snapshot_id'],'files':saved['watched_files'],'snapshot':saved['local_storage_snapshot'],
             'installed_files':{str(k):v for k,v in ip['watch'].files.items()}},sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'download_metadata':{'status':'not_available_at_exact_saved_cache_reference','expected_decoded_bytes':size,
             'expected_ckey':keys[0],'content_identity_revalidated':False,'absence_is_not_game_object_missing_or_corrupt':True},
        'diagnostic_projection':None,'target_Download_tag_projection_computed':False,
        'scope':{'game_metadata_files_read':2,'game_metadata_bytes_read':ip['watch'].read_bytes,
             'saved_download_metadata_bytes_read':0,'saved_download_metadata_max_bytes':MAX_MANIFEST,
             'archive_payload_bytes_read':0,'archive_payload_read_calls':0,'archive_scan_restarted':False,
             'existing_snapshot_directory_names_and_stats_rechecked':True,'inventory_database_rebuilt':False,
             'raw_paths_account_labels_or_tags_exported':False},
        'actual_required_install_set_known':False,'required_network_download_bytes':None,
        'fresh_local_content_verified':False,'old_success_flags_used_for_content_proof':False,
        'installed_files_health_proven':False,'active_CASC_generation_proven':False,
        'publisher_authentication_proven':False,'vendor_install_policy_proven':False,
        'consistency_model':'saved_file_set_and_stat_fingerprints_not_OS_snapshot_or_hostile_writer_protection',
        'unknown_is_not_missing_or_corrupt':True,'network_requests':0,'lab_files_modified':False,
        'game_files_modified':False,'apply_authorized':False,'installation_ready':False}
    try:manifest.lstat()
    except FileNotFoundError:pass
    else:
        path=w.file(manifest);before=w.files[path];b.need(before[2]==size,'saved_download_size_conflict')
        with path.open('rb') as f:
            b.need(b.fp(os.fstat(f.fileno()))==before,'saved_download_changed')
            reader=ManifestReader(f,size,checked)
            projection=parse_manifest(reader,installed['profile'],progress=progress)
            b.need(reader.md5.hexdigest()==keys[0],'saved_download_ckey_mismatch')
            b.need(b.fp(os.fstat(f.fileno()))==before,'saved_download_changed')
        w.check();report['download_metadata'].update(status='decoded_content_identity_revalidated',content_identity_revalidated=True,sha256=reader.sha.hexdigest())
        report['scope']['saved_download_metadata_bytes_read']=reader.used
        report.update(status='bound_download_diagnostic_projection_complete',diagnostic_projection=projection,target_Download_tag_projection_computed=True)
    progress('final_input_recheck');checked();w.check()
    private['watched_files']=[{'path':str(k),'fingerprint':v} for k,v in w.files.items()]
    # An absent exact cache reference must remain absent through publication.
    private['absent_download_path']=str(manifest) if report['diagnostic_projection'] is None else None
    return report,private

def final_check(private):
    w=reconstruct(private);missing=private['absent_download_path']
    if missing is not None:b.need(not os.path.lexists(missing),'download_metadata_appeared_retry_required')
    return w

def publish(report,private,out,*,progress=lambda _:None):
    progress('prepare_report_output');out=Path(os.path.abspath(str(out)))
    for root in private['protected_roots']:
        root=Path(root);b.need(out!=root and root not in out.parents and out not in root.parents,'scope_output_overlaps_input')
    for root in (out,*out.parents):
        b.need(not(root/'.build.info').exists() and not(root/'.build.db').exists() and not(root/'LAB-ONLY.json').exists(),'scope_output_in_game_or_lab')
    existing=out
    while not os.path.lexists(existing):existing=existing.parent
    b.safe(existing);b.need(not os.path.lexists(out),'scope_new_output_required');final_check(private)
    out.mkdir(parents=True);temp=out/('scope-'+uuid.uuid4().hex+'.pending');final=out/'SCOPE-REVIEW-to-share.json';published=False
    try:
        progress('write_pending_report')
        with temp.open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        final_check(private);progress('publish_report_noreplace');p.publish_noreplace(temp,final);published=True
        progress('postpublication_recheck');final_check(private)
    except BaseException:
        if published:final.unlink()
        raise
    finally:
        if temp.exists():temp.unlink()
    return final

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('lab','audit-dir','game-root'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--out-new',type=Path);x=parser.parse_args();prog=Progress()
    try:
        q,private=review(x.lab,x.audit_dir,x.game_root,progress=prog.mark)
        if x.out_new is not None:publish(q,private,x.out_new,progress=prog.mark)
        print(json.dumps(q,indent=2));return 0
    except KeyboardInterrupt:print(json.dumps({'status':'cancelled_safely','installation_ready':False}));return 130
    except Exception as ex:print(json.dumps(public_error(ex,prog.stage)));return 1
if __name__=='__main__':raise SystemExit(main())
