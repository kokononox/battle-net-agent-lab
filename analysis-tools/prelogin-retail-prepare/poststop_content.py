"""Offline read-only content witness, only AFTER native Job drain.
No HTTP/socket/process execution in this verifier. Never publish names or paths.
CASC prefix indexes select candidates only; full EKey/chunks + CKey required.
"""
import hashlib,json,os,re,stat,sys,threading,time
from pathlib import Path
import content_probe as cp,guard_report as gr
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'downloader'))
import repair_core as core,local_casc as lc,decoded_payload
MAX_ENTRIES=2048
MAX_READ=320*1024**2
MAX_INDEX=4*1024**2
MAX_INDEX_TOTAL=16*1024**2
MANIFESTS={
 'encoding':dict(ckey='d724eae8fcffe481ec76d8a80b7b7bb9',ekey='09bbef079e2e00af0b4796c3594fe938',decoded=200240171,encoded=188058470),
 'download':dict(ckey='d2637fca813744c0c0658002bd1709c6',ekey='24417f9055f24ef9a0e3369018ffc5c1',decoded=74562380,encoded=63424656),
 'install':dict(ckey='8fef5697abe6472c6b9235a2b9f7c9f8',ekey='77d2e5d7fb7ea30d9361fb258ceb56c0',decoded=24078,encoded=23106)}
FIXED_FALSE=('same_file_socket_delivery_proven','complete_game_installation_proven','hardware_upload_proven','downloader_identity_proven','file_absence_proven','raw_paths_exported','payload_exported','game_files_written','network_requested')
def blank(source,run):
 r=dict(schema='bnet-retail-poststop-content-1',source_commit=source,run_id=run,status='pending',job_drained_verified=False,owned_empty_baseline_verified=False,build_reference_matched=False,entries=0,files=0,bytes_read=0,index_files=0,index_checksums_verified=0,prefix_candidates=0,hash_checks=0,entry_limit_reached=False,read_limit_reached=False,objects={k:False for k in ('build_config',*MANIFESTS,*cp.PATHS)},official_metadata_materialized=False,official_component_materialized=False,offline_time_limit_seconds=20)
 r.update({k:False for k in FIXED_FALSE});return r

def validate(r):
 if type(r)is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-retail-poststop-content-1':raise ValueError('post_schema')
 gr.identity(r)
 if r['status']not in {'pending','completed','bounded','refused'}or r['offline_time_limit_seconds']!=20:raise ValueError('post_status')
 for k,cap in [('entries',MAX_ENTRIES),('files',MAX_ENTRIES),('bytes_read',MAX_READ),('index_files',64),('index_checksums_verified',64),('prefix_candidates',32),('hash_checks',32)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('post_count')
 for k in ('job_drained_verified','owned_empty_baseline_verified','build_reference_matched','entry_limit_reached','read_limit_reached','official_metadata_materialized','official_component_materialized'):
  if type(r[k])is not bool:raise ValueError('post_bool')
 if any(r[k]is not False for k in FIXED_FALSE):raise ValueError('post_fixed')
 if type(r['objects'])is not dict or set(r['objects'])!=set(blank('a'*40,'1')['objects'])or any(type(v)is not bool for v in r['objects'].values()):raise ValueError('post_objects')
 if r['official_metadata_materialized']!=any(r['objects'][k]for k in ('build_config',*MANIFESTS))or r['official_component_materialized']!=any(r['objects'][k]for k in cp.PATHS):raise ValueError('post_proof')
 if any(r['objects'].values())and not all(r[k]for k in ('job_drained_verified','owned_empty_baseline_verified','build_reference_matched')):raise ValueError('post_prerequisite')
 if r['index_checksums_verified']>r['index_files']or r['files']>r['entries']:raise ValueError('post_relation')
 return r

def save(r,path='output/retail-poststop.json'):
 validate(r);p=Path(path);tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(r,indent=2)+'\n');tmp.replace(p)

def bind(target,metadata,source,run):
 if os.environ.get('RETAIL_POSTSTOP_CONTENT')!='owned-offline-t11':raise ValueError('post_scope')
 target=core.safe(target);s=target.stat();ref=cp.reference()
 if not stat.S_ISDIR(s.st_mode)or any(target.iterdir())or any(metadata.get(k)!=ref[k]for k in ('build_config','version')):raise ValueError('post_baseline')
 # Private ownership record; never uploaded. No externally supplied path accepted later.
 r=dict(source_commit=source,run_id=run,device=s.st_dev,inode=s.st_ino,empty=True,build_config=ref['build_config'],version=ref['version'])
 Path('output/retail-poststop-owner.private.json').write_text(json.dumps(r))

def prerequisites(observation,owner,target,source,run):
 gr.receipt(observation);gr.identity(owner);ref=cp.reference()
 if any(x.get('source_commit')!=source or x.get('run_id')!=run for x in (observation,owner)):raise ValueError('post_identity')
 if observation['mode']!='observe'or not observation['job_drained']or observation['final_active_processes']!=0 or not observation['termination_requested']or not observation['job_kill_on_close_configured']:raise ValueError('post_job_alive')
 if observation.get('budget_profile')!='approved-2g-512m-t9':raise ValueError('post_budget')
 target=core.safe(target);s=target.stat()
 if not stat.S_ISDIR(s.st_mode)or owner.get('empty')is not True or (s.st_dev,s.st_ino)!=(owner.get('device'),owner.get('inode'))or any(owner.get(k)!=ref[k]for k in ('build_config','version')):raise ValueError('post_owner')
 return target

class Bounded(Exception):pass
class Sink:
 def write(self,b):return len(b)
class Reader:
 def __init__(self,file,audit):self.file=file;self.audit=audit
 def read(self,n):
  self.audit.check()
  if n<0 or self.audit.r['bytes_read']+n>MAX_READ:self.audit.r['read_limit_reached']=True;raise Bounded()
  b=self.file.read(n);self.audit.r['bytes_read']+=len(b);return b
class Audit:
 def __init__(self,r):self.r=r;self.deadline=time.monotonic()+20;self.cancel=threading.Event()
 def check(self):
  if time.monotonic()>=self.deadline:raise Bounded()
 def proof(self,label):
  self.r['objects'][label]=True;self.r['official_metadata_materialized']=any(self.r['objects'][k]for k in ('build_config',*MANIFESTS));self.r['official_component_materialized']=any(self.r['objects'][k]for k in cp.PATHS);save(self.r)
 def hash_region(self,path,offset,size,key):
  if self.r['hash_checks']>=32:raise Bounded()
  self.r['hash_checks']+=1;p=core.regular(path);fp=core.fingerprint(p.stat())
  if offset<0 or size<0 or offset+size>fp[2]:return False
  h=hashlib.md5()
  with p.open('rb')as f:
   if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
   f.seek(offset);reader=Reader(f,self);left=size
   while left:
    b=reader.read(min(65536,left))
    if not b:return False
    h.update(b);left-=len(b)
   if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
  if core.fingerprint(core.regular(p).stat())!=fp:raise core.RepairError('source_changed')
  return h.hexdigest()==key
 def encoded(self,path,offset,label):
  if self.r['objects'][label]:return
  spec=MANIFESTS[label];p=core.regular(path);fp=core.fingerprint(p.stat())
  if offset<0 or offset+spec['encoded']>fp[2]:return
  if self.r['hash_checks']>=32:raise Bounded()
  self.r['hash_checks']+=1
  try:
   with p.open('rb')as f:
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
    f.seek(offset);reader=Reader(f,self)
    proof=decoded_payload.extract(reader,spec['encoded'],spec['decoded'],bytes.fromhex(spec['ckey']),bytes.fromhex(spec['ekey']),self.cancel,Sink())
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
   if core.fingerprint(core.regular(p).stat())!=fp:raise core.RepairError('source_changed')
   if proof['status']=='content_verified':self.proof(label)
  except decoded_payload.PayloadError:pass
 def scan(self,target):
  files=[]
  def walk(folder,depth):
   self.check()
   if depth>8:raise Bounded()
   with os.scandir(core.safe(folder))as items:
    for item in items:
     self.check()
     if self.r['entries']>=MAX_ENTRIES:self.r['entry_limit_reached']=True;raise Bounded()
     self.r['entries']+=1;p=core.safe(Path(folder)/item.name);s=p.lstat()
     if stat.S_ISDIR(s.st_mode):walk(p,depth+1)
     else:core.regular(p);self.r['files']+=1;files.append((p,s.st_size))
  walk(target,0)
  refs=cp.reference()
  for p,size in files:
   self.check()
   if size==87836 and not self.r['objects']['build_config']and self.hash_region(p,0,size,refs['build_config']):self.proof('build_config')
   for label,spec in MANIFESTS.items():
    if self.r['objects'][label]:continue
    if size==spec['decoded']and self.hash_region(p,0,size,spec['ckey']):self.proof(label)
    elif size==spec['encoded']:self.encoded(p,0,label)
   for label,variants in refs['components'].items():
    if not self.r['objects'][label]:
     for v in variants:
      if size==v['size']and self.hash_region(p,0,size,v['ckey']):self.proof(label);break
  total=0
  for p,size in files:
   if not lc.IDX.fullmatch(p.name):continue
   if self.r['index_files']>=64 or size>MAX_INDEX or total+size>MAX_INDEX_TOTAL:raise Bounded()
   self.r['index_files']+=1;total+=size;fp=core.fingerprint(core.regular(p).stat())
   with p.open('rb')as f:
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
    raw=Reader(f,self).read(size)
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
   if core.fingerprint(core.regular(p).stat())!=fp:raise core.RepairError('source_changed')
   proof=lc.index_proof(raw,p.name,self.cancel)
   if not proof['checksum_verified']:continue
   self.r['index_checksums_verified']+=1
   for i in range(proof['entries']):
    self.check();entry=raw[40+i*18:58+i*18];packed=int.from_bytes(entry[9:14],'big');aid=packed>>30;offset=packed&((1<<30)-1);span=int.from_bytes(entry[14:],'little')
    for label,spec in MANIFESTS.items():
     if self.r['objects'][label]or entry[:9]!=bytes.fromhex(spec['ekey'])[:9]or span not in (spec['encoded'],spec['encoded']+30):continue
     if self.r['prefix_candidates']>=32:raise Bounded()
     self.r['prefix_candidates']+=1
     # Fixed archive basename only, same verified directory; no path from index.
     if aid>=1024:continue
     archive=core.safe(p.parent/('data.%03d'%aid))
     if archive.exists():self.encoded(archive,offset+(30 if span==spec['encoded']+30 else 0),label)

def main():
 source=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];r=blank(source,run)
 try:
  if os.environ.get('RETAIL_POSTSTOP_CONTENT')!='owned-offline-t11'or os.environ.get('RETAIL_BUDGET_PROFILE')!='approved-2g-512m-t9':raise ValueError('post_scope')
  o=gr.read('output/retail-supervisor-observe.json');owner=gr.read('output/retail-poststop-owner.private.json')
  root=Path(os.environ['RUNNER_TEMP'])
  if not root.is_absolute():raise ValueError('post_root')
  target=prerequisites(o,owner,root/'retail-form-c10',source,run)
  r.update(job_drained_verified=True,owned_empty_baseline_verified=True,build_reference_matched=True);save(r)
  try:Audit(r).scan(target);r['status']='completed'
  except Bounded:r['status']='bounded'
 except Exception:r['status']='refused'
 save(r)
 return 0 if r['status']in {'completed','bounded'}else 2
if __name__=='__main__':
 if len(sys.argv)>1:
  r=validate(gr.read(sys.argv[1]))
  if len(sys.argv)!=5 or r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]:raise ValueError('post_identity')
  Path(sys.argv[2]).write_text(json.dumps(r,indent=2)+'\n')
 else:raise SystemExit(main())
