"""Offline prefix/size/stat candidate index. NEVER proof of reusable content.
Reads only explicitly pinned uploaded .idx members; no archive/shmem/LRU reads.
No choosing a duplicate locator, guessing active generation, or crediting bytes.
"""
import hashlib,json,re,sqlite3,zipfile
from pathlib import Path
from urllib.parse import quote
from datetime import datetime,timezone
from release_core import need,strict_json,TargetSnapshot
from local_candidates import parse_v7


def sha_file(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def archive_stats(raw):
 need(type(raw)is bytes and 0<len(raw)<=65536,'reuse_stat_budget');r=strict_json(raw);need(r.get('format')=='windows-storage-stat-only-1' and r.get('status')=='three_direct_storage_directories_reviewed_NOT_content_proof','reuse_stat_format')
 folders=r.get('folders');need(type(folders)is list,'reuse_stat_folders');selected=[x for x in folders if type(x)is dict and x.get('relative_directory')=='Data/data'];need(len(selected)==1,'reuse_stat_directory_ambiguous');files=selected[0].get('files');need(type(files)is list and len(files)<=4096,'reuse_stat_row_limit');seen=set();archives={}
 for row in files:
  need(type(row)is dict and type(row.get('name'))is str and row['name']not in seen,'reuse_stat_duplicate_name');seen.add(row['name'])
  if row.get('kind')!='archive':continue
  need(re.fullmatch(r'data\.[0-9]{3}',row['name'])is not None and type(row.get('bytes'))is int and 0<=row['bytes']<=2**63-1,'reuse_stat_archive_geometry');archives[int(row['name'][5:])]=row['bytes']
 need(bool(archives),'reuse_stat_no_archives');return archives


def classify_candidates(db):
 """Input tables target_objects,local_refs,archive_sizes; output ALL unknown.
 Candidate flags indicate which bounded bytes could be checked in a later scope.
 """
 db.executescript('''CREATE INDEX refs_prefix ON local_refs(prefix);
 CREATE TABLE candidate_states AS
 SELECT t.ekey,t.encoded_size,
 count(r.ordinal) AS prefix_reference_rows,
 sum(CASE WHEN r.span IN(t.encoded_size,t.encoded_size+30) THEN 1 ELSE 0 END) AS size_compatible_rows,
 sum(CASE WHEN r.span=t.encoded_size AND a.bytes IS NOT NULL AND r.offset<=a.bytes AND r.span<=a.bytes-r.offset THEN 1 ELSE 0 END) AS direct_in_reported_bounds_rows,
 sum(CASE WHEN r.span=t.encoded_size+30 AND a.bytes IS NOT NULL AND r.offset<=a.bytes AND r.span<=a.bytes-r.offset THEN 1 ELSE 0 END) AS prefix30_in_reported_bounds_rows,
 sum(CASE WHEN r.span IN(t.encoded_size,t.encoded_size+30) AND a.bytes IS NULL THEN 1 ELSE 0 END) AS compatible_without_stat_rows
 FROM target_objects t LEFT JOIN local_refs r ON r.prefix=t.prefix LEFT JOIN archive_sizes a ON a.archive_id=r.archive_id GROUP BY t.ekey;
 CREATE UNIQUE INDEX candidate_by_ekey ON candidate_states(ekey);
 ''')
 def n(q):return db.execute(q).fetchone()[0]
 total=n('SELECT count(*) FROM target_objects');need(n('SELECT count(*) FROM candidate_states')==total,'reuse_target_cardinality')
 return {'candidate_target_objects':total,'with_any_prefix_reference':n('SELECT count(*) FROM candidate_states WHERE prefix_reference_rows>0'),'without_reference_in_uploaded_copy_UNKNOWN':n('SELECT count(*) FROM candidate_states WHERE prefix_reference_rows=0'),'with_size_and_reported_bounds_candidate_NOT_content_proof':n('SELECT count(*) FROM candidate_states WHERE direct_in_reported_bounds_rows+prefix30_in_reported_bounds_rows>0'),'with_multiple_compatible_bounded_locators_NOT_arbitrarily_selected':n('SELECT count(*) FROM candidate_states WHERE direct_in_reported_bounds_rows+prefix30_in_reported_bounds_rows>1'),'with_compatible_locator_but_missing_stat_UNKNOWN':n('SELECT count(*) FROM candidate_states WHERE compatible_without_stat_rows>0'),'target_prefix_collision_groups':n('SELECT count(*) FROM(SELECT prefix FROM target_objects GROUP BY prefix HAVING count(*)>1)'),'current_disk_state_proven':False,'active_generation_proven':False,'reuse_authorized_objects':0,'proven_missing_objects':0,'reuse_credit_bytes':0,'required_network_download_bytes':None,'absence_is_proof_of_missing_content':False,'all_dispositions':'unknown_until_full_identity_and_fresh_coherent_backend_proof','installation_ready':False,'apply_authorized':False}


def build_reuse_candidates(plan_dir,index_zip,old_index_report,stat_report,out):
 plan_dir,index_zip,old_index_report,stat_report,out=map(Path,(plan_dir,index_zip,old_index_report,stat_report,out));need(not out.exists(),'reuse_output_exists');plan=json.loads((plan_dir/'CANDIDATE-PLAN-to-share.json').read_bytes());TargetSnapshot.restore(plan['target']);need(plan['status']=='candidate_selection_and_crosswalk_checked_NOT_vendor_required_set' and plan['required_set_selected']is False,'reuse_candidate_plan_required');source=plan_dir/'CANDIDATE-PLAN.sqlite';need(source.is_file()and not source.is_symlink()and source.stat().st_size==plan['database']['bytes']and sha_file(source)==plan['database']['sha256'],'reuse_plan_database_identity')
 prior=json.loads(old_index_report.read_bytes());need(prior.get('format')=='uploaded-primary-data-index-review-1'and prior.get('status')=='v7_index_blocks_verified_LOCAL_PAYLOAD_NOT_READ','reuse_index_evidence_format');need(sha_file(index_zip)==prior['source_zip_sha256'],'reuse_uploaded_zip_identity');stat_raw=stat_report.read_bytes();need(hashlib.sha256(stat_raw).hexdigest()==prior['stat_report_sha256'],'reuse_stat_identity');sizes=archive_stats(stat_raw);expected={r['name']:r for r in prior['indexes']};need(len(expected)==len(prior['indexes'])==16,'reuse_index_count');out.mkdir(exist_ok=False);dbpath=out/'REUSE-CANDIDATES.partial.sqlite';dbpath.touch(exist_ok=False);db=sqlite3.connect(str(dbpath),uri=True);proofs=[]
 try:
  db.executescript('PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; CREATE TABLE local_refs(member TEXT,ordinal INTEGER,prefix BLOB NOT NULL,archive_id INTEGER,offset INTEGER,span INTEGER,PRIMARY KEY(member,ordinal)) WITHOUT ROWID; CREATE TABLE archive_sizes(archive_id INTEGER PRIMARY KEY,bytes INTEGER); CREATE TABLE target_objects(ekey BLOB PRIMARY KEY,prefix BLOB,encoded_size INTEGER) WITHOUT ROWID; CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);')
  db.execute('ATTACH DATABASE ? AS src',('file:'+quote(str(source.resolve()))+'?mode=ro',));db.execute('INSERT INTO target_objects SELECT ekey,substr(ekey,1,9),encoded_size FROM src.selected_download');db.executemany('INSERT INTO archive_sizes VALUES(?,?)',sizes.items());db.commit()
  with zipfile.ZipFile(index_zip)as z:
   infos=[i for i in z.infolist()if i.filename in expected];need(len(infos)==16 and len(set(i.filename for i in infos))==16,'reuse_uploaded_members_ambiguous')
   for info in sorted(infos,key=lambda i:i.filename):
    e=expected[info.filename];need(not info.flag_bits&1 and re.fullmatch('[0-9a-f]{10}\\.idx',info.filename)is not None and info.file_size==e['bytes']<=4*1024**2,'reuse_uploaded_member_bounds')
    # Never testzip(): that would read unapproved shmem/LRU members too.
    with z.open(info)as f:raw=f.read(info.file_size+1)
    need(len(raw)==info.file_size and hashlib.sha256(raw).hexdigest()==e['sha256'],'reuse_uploaded_index_identity');refs,proof=parse_v7(raw,info.filename);need(len(refs)==e['entries'],'reuse_index_record_count');proofs.append(proof)
    for pos in range(0,len(refs),8192):db.executemany('INSERT INTO local_refs(prefix,archive_id,offset,span,member,ordinal) VALUES(?,?,?,?,?,?)',((r.prefix,r.archive_id,r.offset,r.span,info.filename,r.ordinal)for r in refs[pos:pos+8192]))
    db.commit();print(json.dumps({'uploaded_index_verified':info.filename,'records':len(refs)}),flush=True)
  metrics=classify_candidates(db);need(sha_file(source)==plan['database']['sha256'],'reuse_plan_database_changed');report={'format':'offline-uploaded-reuse-candidate-review-1','status':'copied_index_locators_classified_NOT_reuse_proof','target':plan['target'],'candidate_plan_database_sha256':plan['database']['sha256'],'uploaded_zip_sha256':prior['source_zip_sha256'],'historical_stat_report_sha256':prior['stat_report_sha256'],'index_members_read':16,'index_body_bytes_read':sum(e['bytes']for e in expected.values()),'local_reference_rows':sum(p['records']for p in proofs),'indexes':proofs,'metrics':metrics,'full_encoded_keys_reverified_from_local_payload':0,'local_archive_payload_bytes_read':0,'shmem_bytes_read':0,'lru_bytes_read':0,'live_game_access':False,'network_requests':0,'vendor_selection_policy_qualified':False,'required_set_selected':False,'installation_ready':False,'apply_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()}
  db.executemany('INSERT INTO metadata VALUES(?,?)',((k,json.dumps(v,sort_keys=True))for k,v in report.items()));db.commit();need(db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','reuse_database_integrity');db.close();dbpath.rename(out/'REUSE-CANDIDATES.sqlite');report['database']={'bytes':(out/'REUSE-CANDIDATES.sqlite').stat().st_size,'sha256':sha_file(out/'REUSE-CANDIDATES.sqlite'),'integrity_check':'ok'};(out/'REUSE-CANDIDATES-to-share.json').write_text(json.dumps(report,indent=2));return report
 finally:db.close()
