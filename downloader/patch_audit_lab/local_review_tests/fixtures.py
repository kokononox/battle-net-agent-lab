"""GENERATED Lab DBs around two real Portable objects, NOT a user's Lab.
Selection, old success flags and database rows are synthetic test setup.
"""
from pathlib import Path
import json,sqlite3,uuid
from contextlib import closing
import source_binding as b
import staging_sample as s
TARGET='faedca88d0a0ab30dae5519239582d31'
def write_db(path,sql,meta,rows):
 db=sqlite3.connect(path);db.executescript('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);'+sql)
 db.executemany('INSERT INTO metadata VALUES (?,?)',[(k,json.dumps(v)) for k,v in meta.items()])
 for statement,values in rows:db.executemany(statement,values)
 db.commit();db.close()
def contents(root):return {str(p.relative_to(root)):(p.read_bytes(),b.fp(p.stat())) for p in root.rglob('*') if p.is_file()}
class Fixture:
 def __init__(self,root,binding,archive_bytes,*,committed=False,claims=True):
  self.root=root;self.lab=root/'lab';self.objects=self.lab/'objects';self.objects.mkdir(parents=True)
  self.storage=root/'storage';self.storage.mkdir();self.archive=self.storage/'data.000';self.archive.write_bytes(archive_bytes)
  self.binding=binding;self.pid='content-plan-'+uuid.uuid4().hex;self.plan=self.objects/(self.pid+'.sqlite')
  self.queue=self.objects/('acquisition-queue-'+uuid.uuid4().hex+'.sqlite');self.inv=self.objects/('local-casc-inventory-'+uuid.uuid4().hex+'.sqlite');self.ev=self.objects/('local-casc-evidence-'+uuid.uuid4().hex+'.sqlite')
  self.sid=uuid.uuid4().hex
  (self.lab/'LAB-ONLY.json').write_text(json.dumps({'format':'wow-repair-lab-1','real_game_installation':False,'id':uuid.uuid4().hex}))
  rows=[(bytes.fromhex(s.OPTION['source_ekey']),bytes.fromhex(s.OBSERVED['derived_source_ckey']),158,33940,'mapped',1,'archive_range'),(bytes.fromhex(TARGET),bytes.fromhex(s.OPTION['target_ckey']),158,33940,'mapped',1,'archive_range')]
  write_db(self.plan,'CREATE TABLE plan(ekey BLOB PRIMARY KEY,ckey BLOB,encoded_size INTEGER,decoded_size INTEGER,mapping_state TEXT,transfer_supported INTEGER,route_kind TEXT);',
   {'target_binding':binding,'plan_id':self.pid,'plan_summary':{'selected_unique_objects':2,'tag_selection':{'policy':'SYNTHETIC_two_object_test_selection_NOT_Download_manifest'}}},[('INSERT INTO plan VALUES (?,?,?,?,?,?,?)',rows)])
  # Deliberately claim every object is already available: new adapter must ignore this.
  write_db(self.queue,'CREATE TABLE queue(ekey BLOB PRIMARY KEY,availability TEXT);',{'target_binding':binding,'source_plan_id':self.pid},[('INSERT INTO queue VALUES (?,?)',[(r[0],'encoded_available') for r in rows])])
  entries=[(1,rows[0][0],0,510,158,rows[0][1],33940)]
  if committed:entries.append((2,rows[1][0],0,698,158,rows[1][1],33940))
  write_db(self.inv,'CREATE TABLE archives(archive_id INTEGER PRIMARY KEY,name TEXT,size INTEGER,ambiguous INTEGER);CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB,archive_id INTEGER,payload_offset INTEGER,encoded_size INTEGER,ckey BLOB,decoded_size INTEGER);CREATE INDEX candidate_key ON candidates(ekey);',
   {'target_binding':binding,'source_plan_id':self.pid,'source_snapshot_id':self.sid,'local_storage_snapshot':self.snap()},
   [('INSERT INTO archives VALUES (?,?,?,?)',[(0,'data.000',len(archive_bytes),0)]),('INSERT INTO candidates VALUES (?,?,?,?,?,?,?)',entries)])
  evidence=[(r[0],r[1],'casc_span','encoded_and_decoded_content_verified' if claims else 'unverified_fixture',r[4] if claims else 0,int(claims),int(claims),str(self.archive)) for r in entries]
  write_db(self.ev,'CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB,kind TEXT,state TEXT,bytes_read INTEGER,decoded_content_verified INTEGER,encoded_object_verified INTEGER,source_path TEXT);',
   {'target_binding':binding,'source_plan_id':self.pid,'source_snapshot_id':self.sid,'local_verification_summary':{'candidate_rows_pending':0,'all_discovered_candidates_processed':True}},[('INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)',evidence)])
  self.refresh()
 def snap(self):return {'directory':str(self.storage),'names':['data.000'],'files':{'data.000':b.fp(self.archive.stat())},'directory_identity':b.fp(self.storage.stat())}
 def edit(self,path,sql,args=()):
  with closing(sqlite3.connect(path)) as db:
   with db:db.execute(sql,args)
  self.refresh()
 def refresh(self):
  record={'format':'offline-local-review-1','plan_file':{'name':self.plan.name,'fingerprint':b.fp(self.plan.stat())},'queue_file':{'name':self.queue.name,'fingerprint':b.fp(self.queue.stat())},'local_inventory':{'name':self.inv.name,'fingerprint':b.fp(self.inv.stat())},'latest_local':{'name':self.ev.name,'fingerprint':b.fp(self.ev.stat())},'merged_checkpoint':self.ev.name,'plan_id':self.pid}
  (self.objects/'downloader-ui-session.json').write_text(json.dumps({'format':'queue-downloader-ui-1','plan':self.plan.name,'queue':self.queue.name,'local_review':record}))
 def refresh_snapshot(self):self.edit(self.inv,'UPDATE metadata SET value=? WHERE name=?',(json.dumps(self.snap()),'local_storage_snapshot'))
