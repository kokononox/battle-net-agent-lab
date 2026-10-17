"""Owned SYNTHETIC full-scale metadata; no real user Lab/game/archive bytes."""
from pathlib import Path
from dataclasses import replace
import hashlib,json,resource,sqlite3,sys,time
import saved_object_review as o
import saved_scope_review as s
import pinned_download_model as m
import source_binding as b

def run(out):
 out=Path(out);out.mkdir();n=2_881_619;width=(n+7)//8;tags=m.PINNED_MODEL.tags
 rawpath=out/'SYNTHETIC-download.metadata';md5=hashlib.md5();sha=hashlib.sha256();start=time.monotonic()
 def check():b.need(time.monotonic()-start<o.TIME_LIMIT,'synthetic_stress_timeout')
 with rawpath.open('xb') as f:
  def write(raw):f.write(raw);md5.update(raw);sha.update(raw)
  write(b'DL\x01\x10\0'+n.to_bytes(4,'big')+len(tags).to_bytes(2,'big'))
  for first in range(0,n,4096):
   block=b''.join(hashlib.md5((i+1).to_bytes(16,'big')).digest()+((i%1024)+1).to_bytes(5,'big')+b'\x02' for i in range(first,min(n,first+4096)));write(block)
  for name,kind in tags:write(name.encode()+b'\0'+kind.to_bytes(2,'big')+b'\xff'*width)
 assert rawpath.stat().st_size==m.PINNED_MODEL.decoded_bytes
 synthetic=replace(m.PINNED_MODEL,identity='SYNTHETIC-UNIQUE-STRESS-NOT-USER',ckey=md5.hexdigest(),sha256=sha.hexdigest());sink=[]
 profile={'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']}
 with rawpath.open('rb') as f:
  reader=s.ManifestReader(f,rawpath.stat().st_size,check);q=s.parse_manifest(reader,profile,observe_unresolved=True,pinned_model=synthetic,_selection_sink=sink.append)
 assert q['diagnostic_selected_records']==n and len(sink)==1 and reader.md5.hexdigest()==md5.hexdigest()
 with rawpath.open('rb') as f:
  try:s.parse_manifest(s.ManifestReader(f,rawpath.stat().st_size,check),profile,observe_unresolved=True,pinned_model=m.PINNED_MODEL)
  except b.BindingError as ex:assert str(ex)=='pinned_model_ckey_mismatch'
  else:raise AssertionError('production pin accepted synthetic bytes')
 # Private synthetic source DB. Coordinates are synthetic METADATA ONLY;
 # the claimed archive path does not exist, proving no payload open in this join.
 source=out/('local-casc-inventory-'+'1'*32+'.sqlite');snapshot={'directory':str(out/'NO-ARCHIVE-PRESENT'),'files':{'data.000':[0,0,1048576,0,1]},'names':['data.000'],'directory_identity':[0,0,0,0,1]}
 private={'target':{'fixture':'SYNTHETIC-NOT-USER'},'plan_id':'synthetic-plan','snapshot_id':'synthetic-snapshot','local_storage_snapshot':snapshot,'watched_files':[]}
 src=sqlite3.connect(source)
 src.executescript('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT);CREATE TABLE archives(archive_id INTEGER PRIMARY KEY,name TEXT,size INTEGER,ambiguous INTEGER);CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB,archive_id INTEGER,payload_offset INTEGER,encoded_size INTEGER);CREATE INDEX candidate_key ON candidates(ekey);')
 src.executemany('INSERT INTO metadata VALUES (?,?)',[(k,json.dumps(v)) for k,v in {'target_binding':private['target'],'source_plan_id':private['plan_id'],'source_snapshot_id':private['snapshot_id'],'local_storage_snapshot':snapshot}.items()])
 src.execute('INSERT INTO archives VALUES(0,?,1048576,0)',('data.000',))
 src.executemany('INSERT INTO candidates VALUES (?,?,0,0,?)',[(i,hashlib.md5(i.to_bytes(16,'big')).digest(),((i-1)%1024)+1) for i in range(1,2001)])
 src.commit();src.close();watch=b.Watch();watch.file(source);private['watched_files']=[{'path':str(source),'fingerprint':watch.files[source]}]
 work=out/'private-work.sqlite';db=o.open_work(work,check)
 try:
  with rawpath.open('rb') as f:summary,r=o.collect(db,f,rawpath.stat().st_size,sink[0],check)
  assert r.md5.hexdigest()==md5.hexdigest() and r.sha.hexdigest()==sha.hexdigest()
  summary.update(o.join_inventory(db,private,watch,check));dbbytes=work.stat().st_size
 finally:db.close()
 assert summary['selected_records']==summary['unique_ekeys']==n and summary['duplicate_selected_records']==summary['unique_ekeys_with_conflicting_manifest_sizes']==0
 assert summary['unique_ekeys_by_metadata_state'][o.CATEGORIES[5]]==2000 and summary['unique_ekeys_by_metadata_state'][o.CATEGORIES[2]]==n-2000
 assert sum(summary['unique_ekeys_by_metadata_state'].values())==n and dbbytes<=o.MAX_WORK_DB_BYTES
 def arithmetic_size_total(count):
  blocks,tail=divmod(count,1024);return blocks*(1024*1025//2)+tail*(tail+1)//2
 encoded=summary['encoded_size_projection'];total=arithmetic_size_total(n);listed=arithmetic_size_total(2000)
 assert encoded['complete_for_selected_unique_ekeys'] and encoded['total_selected_unique_encoded_bytes']==total
 assert encoded['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[5]]==listed
 assert encoded['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[2]]==total-listed
 assert summary['required_network_download_bytes'] is None
 work.unlink();watch.check()
 return {'input':'SYNTHETIC unique-EKey Download and inventory metadata; NOT actual user Lab or Download','runtime':'Linux_Python3.13','key_order':'deterministic_MD5_digest_pseudorandom_NOT_sequential_keys','work_cache_target_bytes':o.WORK_CACHE_KIB*1024,'records':n,'unique_selected_ekeys':summary['unique_ekeys'],'metadata_total_unique_encoded_bytes':total,'metadata_listed_encoded_bytes':listed,'metadata_not_listed_unknown_encoded_bytes':total-listed,'independent_closed_form_byte_reconciliation':True,'required_network_download_bytes':None,'listed_with_size_and_snapshot_coordinates':2000,'not_listed_unknown':n-2000,'private_work_database_bytes':dbbytes,'private_work_database_limit_bytes':o.MAX_WORK_DB_BYTES,'private_work_removed':not work.exists(),'production_pin_rejected_synthetic_bytes':True,'pinned_model_override_test_only':True,'normal_tool_metadata_passes':2,'normal_tool_metadata_bytes':2*rawpath.stat().st_size,'additional_synthetic_production_pin_rejection_pass':True,'archive_payload_bytes_read':0,'network_requests':0,'installation_ready':False,'process_peak_rss_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'elapsed_seconds':round(time.monotonic()-start,3),'native_Windows_execution':False}
if __name__=='__main__':print(json.dumps(run(sys.argv[1]),indent=2))
