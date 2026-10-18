"""Build metadata-only crosswalk for any verified supported target, not a required set."""
from pathlib import Path
import hashlib,json,sqlite3,os,datetime
from release_core import need,TargetSnapshot
from config_binding import bind,ManifestDescriptor
from catalogue_readers import parse_install,DownloadReader,EncodingReader

def batches(rows,n=8192):
 group=[]
 for r in rows:
  group.append(r)
  if len(group)==n:yield group;group=[]
 if group:yield group

def build(base,objects):
 receipt=json.loads((objects/'METADATA-VERIFIED-to-share.json').read_bytes());need(receipt.get('format')=='approved-dynamic-metadata-receipt-1' and receipt.get('status')=='three_metadata_objects_identity_and_blte_verified','verified_transfer_receipt_required');snapshot=TargetSnapshot.restore(receipt['target']);bound=bind(snapshot,(base/'observed-build.config').read_bytes(),(base/'observed-cdn.config').read_bytes());specs={s['name']:ManifestDescriptor(**s) for s in bound['manifest_descriptors']};proofs={s['name']:s for s in receipt['metadata']};need(set(specs)==set(proofs)=={'install','download','encoding'},'three_proofs_required');fingerprints={}
 for name,s in specs.items():
  p=objects/(name+'.decoded');need(p.is_file() and not p.is_symlink() and p.stat().st_size==s.decoded_size,'metadata_input_bounds');before=p.stat();md=hashlib.md5();sha=hashlib.sha256()
  with p.open('rb') as f:
   while raw:=f.read(1048576):md.update(raw);sha.update(raw)
  need(md.hexdigest()==s.ckey==proofs[name]['ckey'] and sha.hexdigest()==proofs[name]['decoded_sha256'],'metadata_input_identity');fingerprints[p]=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
 dbpath=objects/'TARGET-CATALOGUE.sqlite';tmp=objects/'TARGET-CATALOGUE.partial.sqlite';need(not dbpath.exists() and not tmp.exists(),'catalogue_output_exists');tmp.touch(exist_ok=False);db=sqlite3.connect(tmp)
 db.executescript('''PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
 CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
 CREATE TABLE install_entries(record_index INTEGER PRIMARY KEY,label TEXT,ckey BLOB NOT NULL,decoded_size INTEGER NOT NULL);
 CREATE TABLE install_tags(tag_index INTEGER PRIMARY KEY,label TEXT,kind INTEGER,bitmap BLOB);
 CREATE TABLE content_links(ckey BLOB NOT NULL,ekey BLOB NOT NULL,decoded_size INTEGER NOT NULL,PRIMARY KEY(ckey,ekey)) WITHOUT ROWID;
 CREATE TABLE encodings(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL,espec_index INTEGER NOT NULL) WITHOUT ROWID;
 CREATE TABLE especs(espec_index INTEGER PRIMARY KEY,recipe TEXT NOT NULL);
 CREATE TABLE download_records(record_index INTEGER PRIMARY KEY,ekey BLOB NOT NULL,encoded_size INTEGER NOT NULL,priority INTEGER NOT NULL);
 CREATE TABLE download_tags(tag_index INTEGER PRIMARY KEY,label TEXT,kind INTEGER,bitmap BLOB);
 ''')
 def insert(sql,rows):
  for batch in batches(rows):db.executemany(sql,batch)
 tags,entries=parse_install((objects/'install.decoded').read_bytes());insert('INSERT INTO install_tags VALUES(?,?,?,?)',tags);insert('INSERT INTO install_entries VALUES(?,?,?,?)',entries)
 content_records=0
 with (objects/'encoding.decoded').open('rb') as f:
  reader=EncodingReader(f,specs['encoding'].decoded_size);insert('INSERT INTO especs VALUES(?,?)',enumerate(reader.specs));tail=reader.tail
  def links():
   nonlocal content_records
   for ck,size,keys in reader.content():
    content_records+=1
    for ek in keys:yield ck,ek,size
  insert('INSERT INTO content_links VALUES(?,?,?)',links());db.commit();print('content_links_verified_and_imported',flush=True);insert('INSERT INTO encodings VALUES(?,?,?)',reader.encoded());db.commit();print('encoding_records_verified_and_imported',flush=True)
 with (objects/'download.decoded').open('rb') as f:
  reader=DownloadReader(f,specs['download'].decoded_size);insert('INSERT INTO download_records VALUES(?,?,?,?)',reader.records());insert('INSERT INTO download_tags VALUES(?,?,?,?)',reader.tags());db.commit()
 db.executescript('CREATE INDEX content_by_ekey ON content_links(ekey); CREATE INDEX download_by_ekey ON download_records(ekey); CREATE INDEX install_by_ckey ON install_entries(ckey);');print('crosswalk_indexes_created',flush=True)
 def scalar(sql):return db.execute(sql).fetchone()[0]
 counts={t:scalar('SELECT count(*) FROM '+t) for t in ('install_entries','install_tags','content_links','encodings','especs','download_records','download_tags')};counts['content_records']=content_records
 coverage={
  'download_records_missing_encoding':scalar('SELECT count(*) FROM download_records d LEFT JOIN encodings e USING(ekey) WHERE e.ekey IS NULL'),
  'download_encoded_size_conflicts':scalar('SELECT count(*) FROM download_records d JOIN encodings e USING(ekey) WHERE d.encoded_size<>e.encoded_size'),
  'download_records_without_content_link':scalar('SELECT count(*) FROM download_records d WHERE NOT EXISTS(SELECT 1 FROM content_links c WHERE c.ekey=d.ekey)'),
  'content_links_without_encoding':scalar('SELECT count(*) FROM content_links c LEFT JOIN encodings e USING(ekey) WHERE e.ekey IS NULL'),
  'encodings_without_content_link':scalar('SELECT count(*) FROM encodings e WHERE NOT EXISTS(SELECT 1 FROM content_links c WHERE c.ekey=e.ekey)'),
  'encodings_not_in_download':scalar('SELECT count(*) FROM encodings e WHERE NOT EXISTS(SELECT 1 FROM download_records d WHERE d.ekey=e.ekey)'),
  'duplicate_download_key_groups':scalar('SELECT count(*) FROM (SELECT ekey FROM download_records GROUP BY ekey HAVING count(*)>1)'),
  'encoded_keys_with_multiple_content_keys':scalar('SELECT count(*) FROM (SELECT ekey FROM content_links GROUP BY ekey HAVING count(*)>1)'),
  'install_records_without_content_mapping':scalar('SELECT count(*) FROM install_entries i WHERE NOT EXISTS(SELECT 1 FROM content_links c WHERE c.ckey=i.ckey)'),
  'install_decoded_size_conflicts':scalar('SELECT count(*) FROM install_entries i JOIN content_links c USING(ckey) WHERE c.decoded_size<>i.decoded_size'),
  'install_records_without_download_route':scalar('SELECT count(*) FROM install_entries i WHERE NOT EXISTS(SELECT 1 FROM content_links c JOIN download_records d USING(ekey) WHERE c.ckey=i.ckey)')
 }
 status='full_target_metadata_crosswalk_verified' if all(v==0 for k,v in coverage.items() if k!='encodings_not_in_download') else 'metadata_relations_need_review_NOT_game_damage'
 for p,before in fingerprints.items():
  s=p.stat();need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==before,'metadata_changed_during_catalogue_build')
 report={'format':'dynamic-target-catalogue-1','status':status,'target':snapshot.public(),'counts':counts,'coverage':coverage,'encoding_tail':tail,'required_set_selected':False,'local_content_availability_proven':False,'required_download_bytes':None,'game_content_read':False,'game_content_written':False,'installation_ready':False,'apply_authorized':False,'source_metadata_sha256':{n:p['decoded_sha256'] for n,p in proofs.items()},'completed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 db.executemany('INSERT INTO metadata VALUES(?,?)',[(k,json.dumps(v,sort_keys=True)) for k,v in report.items()]);db.commit();need(scalar('PRAGMA integrity_check')=='ok','catalogue_integrity');db.close();tmp.rename(dbpath)
 with dbpath.open('rb') as f:report['database']={'bytes':dbpath.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest(),'integrity_check':'ok'}
 (objects/'CATALOGUE-VERIFIED-to-share.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':status,'counts':counts,'coverage':coverage}),flush=True);return report
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binding-workspace',type=Path,required=True);parser.add_argument('--objects-workspace',type=Path,required=True);args=parser.parse_args();build(args.binding_workspace,args.objects_workspace)
