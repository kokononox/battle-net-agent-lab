"""Read-only unique selected EKeys versus the EXACT saved candidate inventory.

NOT an installer, file-health test, missing-file finder or network-byte plan.
No archive payload, network, scan restart or Lab/game writes. All SQLite work
is in a fresh private directory under the separate new report output.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,os,re,shutil,sqlite3,time,uuid
import saved_scope_review as s
import source_binding as b
VERSION='saved-object-review-1'
MAX_METADATA_READ=256*1024**2
MAX_WORK_DB_BYTES=512*1024**2
MAX_JOIN_ROWS=10_000_000
MAX_ALIASES=64
TIME_LIMIT=600
CATEGORIES=('manifest_size_conflict_unresolved','manifest_zero_size_unresolved',
    'not_listed_in_saved_inventory_unknown','listed_without_size_agreement',
    'listed_without_usable_snapshot_coordinates','listed_with_size_and_snapshot_coordinates')
PHASES=s.PHASES|{'prepare_private_workspace','deduplicate_selected_records',
    'revalidate_download_second_pass','join_saved_inventory','remove_private_workspace'}
class Progress:
    def __init__(self):self.stage='start'
    def mark(self,stage):b.need(stage in PHASES,'object_phase_invalid');self.stage=stage
def public_error(ex,stage='start'):
    q=s.public_error(ex,stage);q['scope_review_version']=VERSION
    q['stage']=stage if stage in PHASES else 'start'
    return q
def new_output(private,out):
    """Reserve only a fresh separate directory; never clean a preexisting path."""
    out=Path(os.path.abspath(str(out)))
    for root in private['protected_roots']:
        root=Path(root);b.need(out!=root and root not in out.parents and out not in root.parents,'object_output_overlaps_input')
    for root in (out,*out.parents):
        b.need(not(root/'.build.info').exists() and not(root/'.build.db').exists() and not(root/'LAB-ONLY.json').exists(),'object_output_in_game_or_lab')
    existing=out
    while not os.path.lexists(existing):existing=existing.parent
    b.safe(existing);b.need(not os.path.lexists(out),'object_new_output_required')
    s.final_check(private);out.mkdir(parents=True)
    return out
def open_work(path,check):
    db=sqlite3.connect(path,uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA page_size=4096')
        db.execute('PRAGMA max_page_count='+str(MAX_WORK_DB_BYTES//4096))
        db.execute('PRAGMA cache_size=-8192');db.execute('PRAGMA temp_store=MEMORY')
        # Private disposable work only; bounded disk, no rollback journal.
        db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA synchronous=OFF')
        db.execute('PRAGMA automatic_index=OFF')
        def sql_check():
            try:check();return 0
            except Exception:return 1
        db.set_progress_handler(sql_check,10000)
        db.execute('CREATE TABLE objects(ekey BLOB PRIMARY KEY,lo INTEGER NOT NULL,hi INTEGER NOT NULL,records INTEGER NOT NULL) WITHOUT ROWID')
        return db
    except BaseException:
        db.close();raise
def collect(db,f,size,selection,check,*,progress=lambda _:None):
    """Second COMPLETE raw-hash pass; only selected record tuples enter work DB."""
    n=selection['records'];mask=selection['mask'];offset=selection['record_offset'];es=selection['entry_size']
    b.need(type(n)is int and 1<=n<=s.MAX_RECORDS and len(mask)==(n+7)//8,'object_selection_shape')
    b.need(offset in (11,12,16) and 22<=es<=30 and offset+n*es<=size,'object_record_table_bounds')
    b.need(not(mask[-1]&((1<<((-n)%8))-1)),'object_selection_padding')
    r=s.ManifestReader(f,size,check);r.read(offset);selected=0
    statement='''INSERT INTO objects VALUES (?,?,?,1) ON CONFLICT(ekey) DO UPDATE SET
        lo=min(lo,excluded.lo),hi=max(hi,excluded.hi),records=records+1'''
    progress('deduplicate_selected_records')
    for start in range(0,n,4096):
        check();count=min(4096,n-start);raw=r.read(count*es);batch=[]
        for j in range(count):
            ordinal=start+j
            if mask[ordinal//8]&(128>>(ordinal%8)):
                entry=raw[j*es:(j+1)*es];ek=entry[:16];encoded=int.from_bytes(entry[16:21],'big')
                b.need(ek!=bytes(16),'object_zero_ekey')
                batch.append((ek,encoded,encoded));selected+=1
        db.executemany(statement,batch)
    progress('revalidate_download_second_pass')
    while r.used<size:check();r.read(min(1024**2,size-r.used))
    db.commit();check()
    row=db.execute('SELECT count(*),coalesce(sum(records),0),coalesce(sum(lo!=hi),0),coalesce(sum(lo=0 AND hi=0),0) FROM objects').fetchone()
    b.need(row[1]==selected,'object_selected_record_reconciliation')
    return {'selected_records':selected,'unique_ekeys':row[0],
        'duplicate_selected_records':selected-row[0],
        'unique_ekeys_with_conflicting_manifest_sizes':row[2],
        'unique_ekeys_with_zero_manifest_size':row[3]},r
def exact_inventory(private):
    rows=[r for r in private['watched_files'] if re.fullmatch(r'local-casc-inventory-[0-9a-f]{32}\.sqlite',Path(r['path']).name)]
    b.need(len(rows)==1,'object_exact_saved_inventory_reference_required')
    return Path(rows[0]['path'])
def coordinate_ok(row,encoded,snapshot):
    cid,ces,aid,offset,name,archive_size,ambiguous=row
    files=snapshot['files']
    return (type(cid)is int and cid>=0 and type(ces)is int and ces==encoded and encoded>0
        and type(aid)is int and aid>=0 and type(offset)is int and offset>=0
        and type(ambiguous)is int and ambiguous==0 and isinstance(name,str)
        and re.fullmatch(r'data\.[0-9]{3,}',name) is not None and name in files
        and type(archive_size)is int and archive_size==files[name][2]
        and offset+encoded<=archive_size)
def join_inventory(db,private,watch,check,*,progress=lambda _:None):
    progress('join_saved_inventory');path=exact_inventory(private);b.attach(db,watch,path,'i')
    b.schema(db,'i','candidates',('id','ekey','archive_id','payload_offset','encoded_size'))
    b.schema(db,'i','archives',('archive_id','name','size','ambiguous'))
    binding=b.metadata(db,'i','target_binding')
    # The base binder already checked the entire four saved binding dictionaries
    # for equality. Retain opaque fields in those DBs; compare the pinned public
    # subset here rather than requiring their deletion or guessing semantics.
    b.need(isinstance(binding,dict) and all(binding.get(k)==v for k,v in private['target'].items())
        and b.metadata(db,'i','source_plan_id')==private['plan_id']
        and b.metadata(db,'i','source_snapshot_id')==private['snapshot_id']
        and b.metadata(db,'i','local_storage_snapshot')==private['local_storage_snapshot'],'object_inventory_binding_conflict')
    indexes=[]
    for row in db.execute('PRAGMA i.index_list(candidates)'):
        name=row[1]
        cols=[r[2] for r in db.execute('PRAGMA i.index_info('+"'"+name.replace("'","''")+"'"+')')]
        if cols and cols[0]=='ekey' and not row[4]:indexes.append(name)
    b.need(indexes,'object_existing_ekey_index_required')
    # Require the known INTEGER PRIMARY KEY archive lookup; no source migration
    # or SQLite automatic index builds on arbitrary schemas.
    archive_cols=list(db.execute('PRAGMA i.table_info(archives)'))
    b.need(any(r[1]=='archive_id' and r[2].upper()=='INTEGER' and r[5]==1 for r in archive_cols),'object_archive_primary_key_required')
    index='"'+sorted(indexes)[0].replace('"','""')+'"'
    counts=Counter({k:0 for k in CATEGORIES});rows_seen=0;keys_with_aliases=0
    # Objects already ordered by their private PK. At most 65 candidate rows
    # per lookup are ever materialized, never a source table-wide scan.
    query='''SELECT c.id,c.encoded_size,c.archive_id,c.payload_offset,a.name,a.size,a.ambiguous
        FROM i.candidates c INDEXED BY '''+index+''' LEFT JOIN i.archives a ON a.archive_id=c.archive_id
        WHERE c.ekey=? LIMIT 65'''
    for ordinal,(ek,lo,hi,records) in enumerate(db.execute('SELECT ekey,lo,hi,records FROM objects')):
        if ordinal%256==0:check()
        rows=db.execute(query,(ek,)).fetchall();rows_seen+=len(rows)
        b.need(len(rows)<=MAX_ALIASES,'object_inventory_alias_limit')
        b.need(rows_seen<=MAX_JOIN_ROWS,'object_inventory_join_row_limit')
        keys_with_aliases+=len(rows)>1
        if lo!=hi:category=CATEGORIES[0]
        elif lo==0:category=CATEGORIES[1]
        elif not rows:category=CATEGORIES[2]
        elif not any(type(r[1])is int and r[1]==lo for r in rows):category=CATEGORIES[3]
        elif not any(coordinate_ok(r,lo,private['local_storage_snapshot']) for r in rows):category=CATEGORIES[4]
        else:category=CATEGORIES[5]
        counts[category]+=1
    check();watch.check()
    total=db.execute('SELECT count(*) FROM objects').fetchone()[0]
    b.need(sum(counts.values())==total,'object_inventory_category_reconciliation')
    return {'unique_ekeys_by_metadata_state':dict(counts),'inventory_candidate_rows_examined':rows_seen,
        'unique_ekeys_with_multiple_inventory_candidates':keys_with_aliases,
        'inventory_is_saved_target_projected_candidates_NOT_complete_installed_object_inventory':True,
        'not_listed_means_unknown_NOT_missing_or_corrupt':True,
        'size_and_coordinates_are_saved_metadata_NOT_fresh_content_proof':True,
        'prior_evidence_success_flags_used':False,'encoded_bytes_verified':False,
        'unique_encoded_size_total_computed':False,'required_network_download_bytes':None}
def run(lab,audit,game,out_new,*,cancel=lambda:False,progress=lambda _:None):
    start=time.monotonic();selection=[]
    def check():b.need(not cancel() and time.monotonic()-start<=TIME_LIMIT,'object_cancelled_or_time_limit')
    def combined_cancel():return cancel() or time.monotonic()-start>TIME_LIMIT
    report,private=s.review(lab,audit,game,cancel=combined_cancel,progress=progress,_selection_sink=selection.append)
    report['base_scope_review_version']=report['scope_review_version'];report['scope_review_version']=VERSION
    report['object_projection']=None;report['selected_unique_object_projection_computed']=False
    report['scope']['saved_download_metadata_total_read_max_bytes']=MAX_METADATA_READ
    # Do not rerun a scan, seek other cache names or accept generic projections.
    can_project=(report['target_Download_tag_projection_computed'] and len(selection)==1)
    if can_project:
        size=report['download_metadata']['expected_decoded_bytes']
        b.need(report['scope']['saved_download_metadata_bytes_read']+size<=MAX_METADATA_READ,'object_metadata_read_budget')
    progress('prepare_private_workspace');out=new_output(private,out_new);work=out/('private-work-'+uuid.uuid4().hex)
    if can_project:
        work.mkdir();db=None
        try:
            check();db=open_work(work/'objects.sqlite',check);watch=s.final_check(private)
            key=report['download_metadata']['expected_ckey']
            path=b.safe(Path(lab)/'objects'/(key+'-'+str(size)+'.decoded'),True)
            b.need(path in watch.files,'object_exact_manifest_watch_required');before=watch.files[path]
            with path.open('rb') as f:
                b.need(b.fp(os.fstat(f.fileno()))==before,'object_manifest_changed')
                summary,reader=collect(db,f,size,selection[0],check,progress=progress)
                b.need(reader.md5.hexdigest()==key and reader.sha.hexdigest()==report['download_metadata']['sha256'],'object_second_pass_content_identity_mismatch')
                b.need(b.fp(os.fstat(f.fileno()))==before,'object_manifest_changed')
            b.need(summary['selected_records']==report['diagnostic_projection']['diagnostic_selected_records'],'object_projection_count_conflict')
            watch.check();summary.update(join_inventory(db,private,watch,check,progress=progress))
            report['scope']['saved_download_metadata_bytes_read']+=reader.used
            report['object_projection']=summary;report['selected_unique_object_projection_computed']=True
            report['diagnostic_projection']['unique_objects_or_duplicate_size_consistency_computed']=True
            report['diagnostic_projection']['unique_object_consistency_scope']='selected_records_only_NOT_unselected_records_or_decoded_content'
            report['status']='bound_selected_unique_objects_inventory_projection_complete'
            private['watched_files']=[{'path':str(k),'fingerprint':v} for k,v in watch.files.items()]
            check();watch.check()
        except sqlite3.Error:
            raise b.BindingError('object_private_or_readonly_database_stopped_safely') from None
        finally:
            if db is not None:db.close()
            shutil.rmtree(work);progress('remove_private_workspace')
    else:
        report['object_projection_not_computed_reason']='pinned_supported_selection_unavailable_no_fallback'
    report['scope'].update(private_work_database_max_bytes=MAX_WORK_DB_BYTES,
        private_work_removed_before_publication=True,selected_ekeys_or_paths_exported=False,
        inventory_database_rebuilt=False)
    progress('final_input_recheck');check();s.final_check(private)
    final=s.publish(report,private,out/'Report',progress=progress)
    progress('complete');return report,final
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('lab','audit-dir','game-root','out-new'):parser.add_argument('--'+name,type=Path,required=True)
    x=parser.parse_args();prog=Progress()
    try:
        q,_=run(x.lab,x.audit_dir,x.game_root,x.out_new,progress=prog.mark)
        print(json.dumps(q,indent=2));return 0
    except KeyboardInterrupt:print(json.dumps({'status':'cancelled_safely','installation_ready':False}));return 130
    except Exception as ex:print(json.dumps(public_error(ex,prog.stage)));return 1
if __name__=='__main__':raise SystemExit(main())