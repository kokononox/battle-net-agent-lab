"""Offline read-only content witness, only AFTER native Job drain.
No HTTP/socket/process execution in this verifier. Never publish names or paths.
CASC prefix indexes select candidates only; full EKey/chunks + CKey required.
"""
import hashlib,json,os,re,stat,sys,threading,time,socket
from pathlib import Path
import content_probe as cp,guard_report as gr
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'downloader'))
import repair_core as core,local_casc as lc,decoded_payload,lookup3
MAX_ENTRIES=2048
MAX_READ=320*1024**2
MAX_INDEX=4*1024**2
MAX_INDEX_TOTAL=16*1024**2
INDEX_STATES=('unsupported_layout','header_checksum_not_verified','entry_checksum_not_verified','continuous_block_checksums_verified')
MANIFESTS={
 'encoding':dict(ckey='d724eae8fcffe481ec76d8a80b7b7bb9',ekey='09bbef079e2e00af0b4796c3594fe938',decoded=200240171,encoded=188058470),
 'download':dict(ckey='d2637fca813744c0c0658002bd1709c6',ekey='24417f9055f24ef9a0e3369018ffc5c1',decoded=74562380,encoded=63424656),
 'install':dict(ckey='8fef5697abe6472c6b9235a2b9f7c9f8',ekey='77d2e5d7fb7ea30d9361fb258ceb56c0',decoded=24078,encoded=23106)}
FIXED_FALSE=('same_file_socket_delivery_proven','complete_game_installation_proven','hardware_upload_proven','downloader_identity_proven','file_absence_proven','raw_paths_exported','payload_exported','game_files_written','network_requested')
def host_seed(suffix=b''):
 # Local OS hostname lookup only. Never DNS/connect, export, or retain clear name.
 return hashlib.md5(socket.gethostname().encode('utf-8')+suffix+b'data/data').digest()[2:9]

def marker_blank():
 return dict(method='hostname_plus_data_path_md5_7byte_crosslink_prediction',prediction_bound_before_form_post=False,local_hostname_prediction_unchanged=False,archive_prefixes_checked=0,records_checked=0,checksum_a_verified_records=0,structural_crosslink_records=0,prediction_matches=0,negative_control_matches=0,archives_with_all_16_predictions=0,host_related_container_marker_observed=False,raw_hostname_exported=False,identifier_digest_exported=False,account_identity_proven=False,globally_unique_machine_identity_proven=False,game_payload_watermark_proven=False,unforgeable_provenance_proven=False)

def blank(source,run):
 r=dict(schema='bnet-retail-poststop-content-2',source_commit=source,run_id=run,status='pending',job_drained_verified=False,owned_empty_baseline_verified=False,build_reference_matched=False,entries=0,files=0,bytes_read=0,index_files=0,index_checksums_verified=0,prefix_candidates=0,hash_checks=0,entry_limit_reached=False,read_limit_reached=False,objects={k:False for k in ('build_config',*MANIFESTS,*cp.PATHS)},official_metadata_materialized=False,official_component_materialized=False,offline_time_limit_seconds=20)
 r['host_marker']=marker_blank();r['index_layout_states']={k:0 for k in INDEX_STATES};r.update({k:False for k in FIXED_FALSE});return r

def validate(r):
 keys=set(blank('a'*40,'1'))
 if type(r)is dict and r.get('schema')=='bnet-retail-poststop-content-1':keys-={'host_marker','index_layout_states'}
 if type(r)is not dict or set(r)!=keys or r['schema']not in {'bnet-retail-poststop-content-1','bnet-retail-poststop-content-2'}:raise ValueError('post_schema')
 gr.identity(r)
 if 'index_layout_states'in r:
  counts=r['index_layout_states']
  if type(counts)is not dict or set(counts)!=set(INDEX_STATES)or any(type(v)is not int or not 0<=v<=64 for v in counts.values())or sum(counts.values())>r['index_files']:raise ValueError('index_diagnostics')
 m=r.get('host_marker',marker_blank())
 if type(m)is not dict or set(m)!=set(marker_blank())or m['method']!=marker_blank()['method']:raise ValueError('marker_schema')
 for k in ('prediction_bound_before_form_post','local_hostname_prediction_unchanged','host_related_container_marker_observed'):
  if type(m[k])is not bool:raise ValueError('marker_bool')
 for k in ('raw_hostname_exported','identifier_digest_exported','account_identity_proven','globally_unique_machine_identity_proven','game_payload_watermark_proven','unforgeable_provenance_proven'):
  if m[k]is not False:raise ValueError('marker_fixed')
 for k,cap in [('archive_prefixes_checked',64),('records_checked',1024),('checksum_a_verified_records',1024),('structural_crosslink_records',1024),('prediction_matches',1024),('negative_control_matches',1024),('archives_with_all_16_predictions',64)]:
  if type(m[k])is not int or not 0<=m[k]<=cap:raise ValueError('marker_count')
 if not 0<=m['prediction_matches']<=m['structural_crosslink_records']<=m['checksum_a_verified_records']<=m['records_checked']<=16*m['archive_prefixes_checked']:raise ValueError('marker_relation')
 positive=m['archives_with_all_16_predictions']>0
 if positive!=m['host_related_container_marker_observed']:raise ValueError('marker_proof')
 if positive and(not m['prediction_bound_before_form_post']or not m['local_hostname_prediction_unchanged']or m['prediction_matches']<16*m['archives_with_all_16_predictions']or m['negative_control_matches']):raise ValueError('marker_prerequisite')
 if positive and not all(r[k]for k in ('job_drained_verified','owned_empty_baseline_verified','build_reference_matched')):raise ValueError('marker_job')
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
 r=dict(source_commit=source,run_id=run,device=s.st_dev,inode=s.st_ino,empty=True,build_config=ref['build_config'],version=ref['version'],host_marker_seed_private=host_seed().hex())
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
 def crosslinks(self,files,prediction):
  marker=self.r['host_marker'];current=host_seed()
  if not re.fullmatch('[0-9a-f]{14}',prediction):raise ValueError('marker_binding')
  seed=bytes.fromhex(prediction);marker['prediction_bound_before_form_post']=True;marker['local_hostname_prediction_unchanged']=seed==current
  if seed!=current:raise ValueError('marker_changed')
  # Negative control changes a locally computed prediction, not source bytes.
  negative=host_seed(b'|bounded-negative-control|')
  if seed==negative:raise ValueError('marker_control_collision')
  for path,size in files:
   match=lc.ARCH.fullmatch(path.name)
   if not match or int(match[1])>255 or size<480:continue
   if marker['archive_prefixes_checked']>=64:raise Bounded()
   self.check();marker['archive_prefixes_checked']+=1;p=core.regular(path);fp=core.fingerprint(p.stat())
   with p.open('rb')as f:
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
    raw=Reader(f,self).read(480)
    if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('source_changed')
   if core.fingerprint(core.regular(p).stat())!=fp:raise core.RepairError('source_changed')
   matched=set();archive=int(match[1])
   for i in range(16):
    header=raw[i*30:(i+1)*30];marker['records_checked']+=1
    if len(header)!=30 or lookup3.hashlittle(header[:22],0x3D6BE971)!=int.from_bytes(header[22:26],'little'):continue
    marker['checksum_a_verified_records']+=1;key=header[:16][::-1]
    if int.from_bytes(header[16:20],'little')!=30 or header[20:22]!=b'\x01\x00'or key[0]>=16 or key[1]!=archive or key[9:]!=bytes(7):continue
    marker['structural_crosslink_records']+=1
    if key[2:9]==negative:marker['negative_control_matches']+=1
    if key[2:9]==seed:marker['prediction_matches']+=1;matched.add(key[0])
   if len(matched)==16:marker['archives_with_all_16_predictions']+=1
  marker['host_related_container_marker_observed']=marker['archives_with_all_16_predictions']>0 and marker['negative_control_matches']==0;save(self.r)
 def scan(self,target,prediction=None):
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
  if prediction is not None:self.crosslinks(files,prediction)
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
   self.r['index_layout_states'][proof['state']]+=1
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
  try:Audit(r).scan(target,owner['host_marker_seed_private']);r['status']='completed'
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
