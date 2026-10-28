"""Read-only, bounded verification of fixed official install-manifest components.
Never creates/copies a game file, follows a game-provided path, or downloads data.
A match proves materialization, NOT that those exact bytes traversed a socket.
"""
import hashlib,json,os,re,sys,time,threading
from pathlib import Path
import guard_report
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'downloader'))
import repair_core as core
PATHS={'voice_proxy':('Utils','WowVoiceProxy.exe'),'exception_handler':('Utils','WowWindowsExceptionHandler.dll'),'client_executable':('Wow.exe',),'client_loader':('wow_loader.dll',)}
LEGACY_COMPONENTS={'voice_proxy','exception_handler'}
REFERENCE_SHA='62df1d03e3d69066a2ad0193b22d1b26459d4293185ebf1c836922d2a9cd0cb1'

def reference():
 raw=Path(__file__).with_name('content_reference.json').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=REFERENCE_SHA:raise ValueError('reference_changed')
 r=json.loads(raw)
 if r['schema']!='bnet-retail-content-reference-1'or r['install_full_ekey_and_ckey_verified']is not True or set(r['components'])!=set(PATHS):raise ValueError('reference')
 return r

def blank(source,run):
 return dict(schema='bnet-retail-content-probe-2',source_commit=source,run_id=run,status='pending',build_reference_matched=False,baseline_checked=False,scans=0,hash_checks=0,hashed_bytes=0,components={k:dict(baseline_absent=False,state='not_observed',observed_bytes=None,matched_ckey=None)for k in PATHS},game_component_materialized=False,network_delivery_of_same_file_proven=False,complete_installation_proven=False,hardware_upload_proven=False,payload_exported=False,raw_paths_exported=False,game_files_written_by_probe=False,race_free_path_safety_proven=False)

def validate(r):
 keys=set(blank('a'*40,'1'))
 if type(r)is dict and 'watcher'in r:keys.add('watcher')
 if type(r)is not dict or set(r)!=keys or r['schema']not in {'bnet-retail-content-probe-1','bnet-retail-content-probe-2'}:raise ValueError('schema')
 guard_report.identity(r)
 if 'watcher'in r:
  w=r['watcher']
  if type(w)is not dict or set(w)!={'status','iterations','interval_ms','time_limit_ms','activation'}or w['status']not in {'observing','bounded_complete','stopped','refused'}or type(w['iterations'])is not int or not 0<=w['iterations']<=64 or w['interval_ms']!=50 or w['time_limit_ms']!=4000 or w['activation']!='before_owned_update_http':raise ValueError('watch_receipt')
 if r['status']not in {'pending','observing','content_verified','no_match_observed','refused'}:raise ValueError('status')
 for k in ('build_reference_matched','baseline_checked','game_component_materialized'):
  if type(r[k])is not bool:raise ValueError('boolean')
 hash_budget=16777216 if r['schema']=='bnet-retail-content-probe-1'else 268435456
 for k,cap in [('scans',64),('hash_checks',8),('hashed_bytes',hash_budget)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('count')
 for k in ('network_delivery_of_same_file_proven','complete_installation_proven','hardware_upload_proven','payload_exported','raw_paths_exported','game_files_written_by_probe','race_free_path_safety_proven'):
  if r[k]is not False:raise ValueError('fixed')
 if type(r['components'])is not dict or set(r['components'])!=(LEGACY_COMPONENTS if r['schema']=='bnet-retail-content-probe-1'else set(PATHS)):raise ValueError('components')
 ref=reference();positive=False
 for label,c in r['components'].items():
  if type(c)is not dict or set(c)!={'baseline_absent','state','observed_bytes','matched_ckey'}or type(c['baseline_absent'])is not bool or c['state']not in {'not_observed','absent','size_mismatch','hash_mismatch','unstable','content_verified'}:raise ValueError('component')
  if c['observed_bytes']is not None and(type(c['observed_bytes'])is not int or not 0<=c['observed_bytes']<=2**50):raise ValueError('size')
  if c['state']=='content_verified':
   if not c['baseline_absent']or not any(v['ckey']==c['matched_ckey']and v['size']==c['observed_bytes']for v in ref['components'][label]):raise ValueError('content_proof')
   positive=True
  elif c['matched_ckey']is not None:raise ValueError('unexpected_hash')
 if r['game_component_materialized']!=positive:raise ValueError('proof_flag')
 if positive and(not r['build_reference_matched']or not r['baseline_checked']or r['hash_checks']<1):raise ValueError('proof_prerequisites')
 if r['status']=='content_verified'and not positive:raise ValueError('status_proof')
 return r

def save(r):
 validate(r);p=Path('output/retail-content.tmp');p.write_text(json.dumps(r,indent=2)+'\n');p.replace('output/retail-content.json')

def digest_exact(path,expected_size):
 path=core.regular(path);before=core.fingerprint(path.stat())
 if before[2]!=expected_size or not 0<expected_size<=134217728:raise core.RepairError('bounded_size')
 md5=hashlib.md5();total=0
 with path.open('rb')as f:
  if core.fingerprint(os.fstat(f.fileno()))!=before:raise core.RepairError('source_changed')
  while total<expected_size:
   block=f.read(min(65536,expected_size-total))
   if not block:raise core.RepairError('source_changed')
   total+=len(block);md5.update(block)
  if f.read(1)or core.fingerprint(os.fstat(f.fileno()))!=before:raise core.RepairError('source_changed')
 if core.fingerprint(core.regular(path).stat())!=before:raise core.RepairError('source_changed')
 return dict(size=total,md5=md5.hexdigest())

class Probe:
 def __init__(self,target,metadata,source,run):
  if os.environ.get('RETAIL_CONTENT_PROBE')!='official-install-t9'or os.environ.get('RETAIL_BUDGET_PROFILE')!='approved-2g-512m-t9':raise ValueError('content_scope')
  self.ref=reference();self.target=core.safe(target);self.r=blank(source,run);self.cache={};self.lock=threading.RLock();self.watch_thread=None;self.watch_stop=threading.Event();self.watch_failed=False
  if metadata is None or any(metadata.get(k)!=self.ref[k]for k in ('build_config','version')):raise ValueError('content_build')
  self.r['build_reference_matched']=True
  for label,parts in PATHS.items():
   for prefix in ((),('_retail_',)):
    p=core.safe(self.target.joinpath(*prefix,*parts))
    if p.exists():raise ValueError('baseline_component_exists')
   self.r['components'][label]['baseline_absent']=True
  self.r['baseline_checked']=True;self.r['status']='observing';save(self.r)
 def scan(self):
  with self.lock:
   if self.watch_failed:raise ValueError('content_watch_refused')
   return self._scan()
 def _scan(self):
  r=self.r
  if r['scans']>=64:return
  r['scans']+=1;save(r)
  try:
   for label,parts in PATHS.items():
    c=r['components'][label]
    if c['state']=='content_verified':continue
    c['state']='absent'
    for prefix in ((),('_retail_',)):
     p=core.safe(self.target.joinpath(*prefix,*parts))
     if not p.exists():continue
     p=core.regular(p);s=p.stat();c['observed_bytes']=s.st_size
     candidates=[v for v in self.ref['components'][label]if v['size']==s.st_size]
     if not candidates:c['state']='size_mismatch';continue
     fp=core.fingerprint(s);cached=self.cache.get((label,prefix))
     if cached is not None and cached[0]==fp:matched=cached[1]
     else:
      if r['hash_checks']>=8 or r['hashed_bytes']+s.st_size>268435456:continue
      r['hash_checks']+=1;r['hashed_bytes']+=s.st_size;save(r)
      try:d=digest_exact(p,s.st_size)
      except core.RepairError:c['state']='unstable';continue
      matched=next((v['ckey']for v in candidates if d['size']==v['size']and d['md5']==v['ckey']),None);self.cache[(label,prefix)]=(fp,matched)
     if matched is not None:c.update(state='content_verified',matched_ckey=matched);r['game_component_materialized']=True;r['status']='content_verified';break
     c['state']='hash_mismatch'
   save(r)
  except Exception:
   r['status']='refused';save(r);raise
 def start_watch(self):
  if os.environ.get('RETAIL_CONTENT_WATCH')!='concurrent-fixed-t10'or self.watch_thread is not None or not self.r['baseline_checked']:raise ValueError('watch_scope')
  with self.lock:
   self.r['watcher']=dict(status='observing',iterations=0,interval_ms=50,time_limit_ms=4000,activation='before_owned_update_http');save(self.r)
  def worker():
   deadline=time.monotonic()+4
   try:
    for _ in range(64):
     if self.watch_stop.is_set()or time.monotonic()>=deadline:break
     with self.lock:
      if self.r['scans']>=64:break
      self.r['watcher']['iterations']+=1;self._scan()
      if self.r['game_component_materialized']:break
     if self.watch_stop.wait(.05):break
    with self.lock:
     self.r['watcher']['status']='stopped'if self.watch_stop.is_set()else'bounded_complete';save(self.r)
   except Exception:
    with self.lock:
     self.watch_failed=True;self.r['status']='refused';self.r['watcher']['status']='refused';save(self.r)
    self.watch_stop.set()
  self.watch_thread=threading.Thread(target=worker,name='fixed-content-witness',daemon=True);self.watch_thread.start()
 def stop_watch(self):
  if self.watch_thread is None:return
  self.watch_stop.set();self.watch_thread.join(timeout=1)
  if self.watch_thread.is_alive():raise ValueError('watch_not_stopped')
 def observe_bounded(self):
  deadline=time.monotonic()+20
  for _ in range(40):
   self.scan()
   if self.r['game_component_materialized']or self.r['scans']>=64 or time.monotonic()>=deadline:return
   time.sleep(.5)
  self.r['status']='no_match_observed';save(self.r)

if __name__=='__main__':
 r=validate(guard_report.read(sys.argv[1]))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
