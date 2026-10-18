"""Fixed uploaded-copy research invocation; no game/archive/shmem read."""
import json,zipfile,re,hashlib,sqlite3
from pathlib import Path
from local_v8_readonly import primary_records,REFERENCE
from release_core import need
p=Path('/data/.agent-service/files/7e86609b-594e-4bfd-b9df-9f14be87ef86/G-World of Warcraft-Data.zip');allrows=[];proofs=[]
with zipfile.ZipFile(p) as z:
 files=[i for i in z.infolist() if re.fullmatch('wow/[0-9a-f]{10}\\.idx',i.filename)];need(len(files)==16,'sixteen_uploaded_v8_members')
 for i in files:
  need(i.file_size==131072 and not i.flag_bits&1,'uploaded_v8_bounds');raw=z.read(i);rows,proof=primary_records(raw,int(i.filename[4:6],16));proof.update(name=i.filename,sha256=hashlib.sha256(raw).hexdigest());proofs.append(proof);allrows.extend((i.filename,r['key'],r['opaque_qword0'],r['opaque_qword1']) for r in rows)
db=sqlite3.connect('file:/data/metadata-70448/TARGET-CATALOGUE.sqlite?mode=ro',uri=True);db.execute('PRAGMA trusted_schema=OFF');matched=[]
for name,key,q0,q1 in allrows:
 rows=db.execute('SELECT e.encoded_size,c.decoded_size FROM encodings e JOIN content_links c USING(ekey) WHERE e.ekey=?',(key,)).fetchall();in_download=db.execute('SELECT count(*) FROM download_records WHERE ekey=?',(key,)).fetchone()[0]
 matched.append({'index':name,'full_key':key.hex(),'metadata_matches':len(rows),'present_in_target_download':bool(in_download),'qwords_left_opaque':True})
db.close();report={'format':'uploaded-v8-primary-review-1','status':'v8_uploaded_primary_records_checksums_verified_NOT_local_content_proof','indexes_verified':len(proofs),'primary_records':len(allrows),'records_with_full_key_in_target_encoding':sum(bool(r['metadata_matches']) for r in matched),'records_with_full_key_in_target_download':sum(r['present_in_target_download'] for r in matched),'target_version':'12.1.5.70448','source':'uploaded Data.zip copies, not live storage snapshot','adapter_scope':'strict primary-only v8 with empty tail; header maxoff preserved opaque; not a general native storage adapter','reference':REFERENCE,'original_agent_executed':False,'archive_bounds_checked':False,'active_generation_proven':False,'game_payload_bytes_read':0,'shmem_bytes_read':0,'installation_ready':False,'required_download_bytes':None,'indexes':proofs,'matches':matched};Path('/data/metadata-70448/V8-PRIMARY-to-share.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('indexes','matches')}))
