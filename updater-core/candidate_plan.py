"""Build an offline candidate DB from identity-checked metadata. Never apply.
A candidate is NOT a vendor-qualified required set or proof of local absence.
No network, filesystem traversal of install labels, or live installation reads.
"""
import hashlib,json,sqlite3
from pathlib import Path
from urllib.parse import quote
from datetime import datetime,timezone
from release_core import need,TargetSnapshot
from config_binding import bind,ManifestDescriptor
from catalogue_readers import parse_install,DownloadReader
from required_set import select_bitmap,install_candidates,parse_expression


def sha_file(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def reference_mask(tags,count,expression):
 """Independent per-bit reference for regression, not vendor policy evidence."""
 clauses=parse_expression(expression);lookup={r[1]:r[3]for r in tags};out=bytearray((count+7)//8)
 for i in range(count):
  byte,flag=i//8,0x80>>(i%8)
  if any(all((lookup[t.name][byte]&flag)!=0 for t in clause if t.name in lookup)for clause in clauses):out[byte]|=flag
 return bytes(out)


def build_candidate(base,objects,out,expression):
 base,objects,out=map(Path,(base,objects,out));need(not out.exists(),'candidate_output_exists')
 receipt=json.loads((objects/'METADATA-VERIFIED-to-share.json').read_bytes());cat=json.loads((objects/'CATALOGUE-VERIFIED-to-share.json').read_bytes());need(receipt['status']=='three_metadata_objects_identity_and_blte_verified' and cat['status']=='full_target_metadata_crosswalk_verified' and cat['target']==receipt['target'],'verified_matching_metadata_and_catalogue_required');t=TargetSnapshot.restore(receipt['target']);binding=bind(t,(base/'observed-build.config').read_bytes(),(base/'observed-cdn.config').read_bytes());proofs={x['name']:x for x in receipt['metadata']};fingerprints={}
 for d in binding['manifest_descriptors']:
  s=ManifestDescriptor(**d);p=objects/(s.name+'.decoded');need(p.is_file()and not p.is_symlink()and p.stat().st_size==s.decoded_size,'candidate_input_file')
  with p.open('rb')as f:need(hashlib.file_digest(f,'md5').hexdigest()==s.ckey==proofs[s.name]['ckey'],'candidate_input_ckey')
  need(sha_file(p)==proofs[s.name]['decoded_sha256'],'candidate_input_sha256');st=p.stat();fingerprints[p]=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
 source=objects/'TARGET-CATALOGUE.sqlite';need(source.is_file()and not source.is_symlink()and source.stat().st_size==cat['database']['bytes']and sha_file(source)==cat['database']['sha256'],'candidate_catalogue_identity')
 tags,entries=parse_install((objects/'install.decoded').read_bytes());ib,ir=select_bitmap(tags,len(entries),expression);need(ib==reference_mask(tags,len(entries),expression),'candidate_install_reference_disagrees');paths=install_candidates(entries,ib)
 out.mkdir(exist_ok=False);dbpath=out/'CANDIDATE-PLAN.partial.sqlite';dbpath.touch(exist_ok=False);db=sqlite3.connect(str(dbpath),uri=True)
 try:
  db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA synchronous=FULL');db.execute('ATTACH DATABASE ? AS src',('file:'+quote(str(source.resolve()))+'?mode=ro',));db.executescript('CREATE TABLE selected_install(record_index INTEGER PRIMARY KEY,relative_path TEXT UNIQUE,ckey BLOB,decoded_size INTEGER); CREATE TABLE selected_download(record_index INTEGER PRIMARY KEY,ekey BLOB UNIQUE,encoded_size INTEGER,priority INTEGER); CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);')
  db.executemany('INSERT INTO selected_install VALUES(?,?,?,?)',((r['record_index'],r['relative_path'],bytes.fromhex(r['ckey']),r['decoded_size'])for r in paths))
  with(objects/'download.decoded').open('rb')as f:
   reader=DownloadReader(f,(objects/'download.decoded').stat().st_size);dtags=list(reader.tags());bits,dr=select_bitmap(dtags,reader.n,expression);need(bits==reference_mask(dtags,reader.n,expression),'candidate_download_reference_disagrees');batch=[]
   for row in reader.records():
    i=row[0]
    if bits[i//8]&(0x80>>(i%8)):
     batch.append(row)
     if len(batch)==8192:db.executemany('INSERT INTO selected_download VALUES(?,?,?,?)',batch);batch=[]
   if batch:db.executemany('INSERT INTO selected_download VALUES(?,?,?,?)',batch)
  db.commit()
  def scalar(q):return db.execute(q).fetchone()[0]
  checks={'download_without_encoding':scalar('SELECT count(*) FROM selected_download d LEFT JOIN src.encodings e USING(ekey) WHERE e.ekey IS NULL'),'download_size_conflicts':scalar('SELECT count(*) FROM selected_download d JOIN src.encodings e USING(ekey) WHERE d.encoded_size<>e.encoded_size'),'install_without_selected_download_route':scalar('SELECT count(*) FROM selected_install i WHERE NOT EXISTS(SELECT 1 FROM src.content_links c JOIN selected_download d USING(ekey) WHERE c.ckey=i.ckey AND c.decoded_size=i.decoded_size)')}
  need(all(v==0 for v in checks.values()),'candidate_crosswalk_conflict')
  for p,before in fingerprints.items():
   st=p.stat();need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)==before,'candidate_input_changed')
  need(sha_file(source)==cat['database']['sha256'],'candidate_catalogue_changed')
  report={'format':'offline-target-candidate-plan-1','status':'candidate_selection_and_crosswalk_checked_NOT_vendor_required_set','target':t.public(),'source_metadata_sha256':cat['source_metadata_sha256'],'source_catalogue_sha256':cat['database']['sha256'],'install_selection':ir,'download_selection':dr,'selected_install_paths':len(paths),'selected_download_objects':scalar('SELECT count(*) FROM selected_download'),'candidate_encoded_bytes_if_all_selected_objects_missing':scalar('SELECT COALESCE(sum(encoded_size),0) FROM selected_download'),'independent_per_bit_reference_agrees':True,'crosswalk_checks':checks,'expression_origin':'public historical profile subset; not live installation preferences','private_optional_qualifiers_omitted':True,'vendor_policy_qualified':False,'required_set_selected':False,'active_generation_proven':False,'fresh_local_reuse_proven':False,'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False,'at_utc':datetime.now(timezone.utc).isoformat()}
  db.executemany('INSERT INTO metadata VALUES(?,?)',((k,json.dumps(v,sort_keys=True))for k,v in report.items()));db.commit();need(scalar('PRAGMA integrity_check')=='ok','candidate_integrity');db.close();dbpath.rename(out/'CANDIDATE-PLAN.sqlite');report['database']={'bytes':(out/'CANDIDATE-PLAN.sqlite').stat().st_size,'sha256':sha_file(out/'CANDIDATE-PLAN.sqlite'),'integrity_check':'ok'};(out/'CANDIDATE-PLAN-to-share.json').write_text(json.dumps(report,indent=2));return report
 finally:db.close()
if __name__=='__main__':
 import argparse
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--binding-workspace',type=Path,required=True);a.add_argument('--objects-workspace',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--expression',required=True);x=a.parse_args();r=build_candidate(x.binding_workspace,x.objects_workspace,x.output,x.expression);print(json.dumps({'status':r['status'],'install_paths':r['selected_install_paths'],'download_objects':r['selected_download_objects']}))
