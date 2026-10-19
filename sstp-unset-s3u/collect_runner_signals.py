"""CI-only fixed-signal scanner. Never emits raw runner log text or paths."""
import datetime as dt,json,os,re,sys
from pathlib import Path
SIGNALS={
 'server_cancel_request':('Job cancellation request ', ' received, cancellation timeout '),
 'worker_cancel_received':('Cancellation/Shutdown message received.',),
 'renew_exception':('Catch exception during renew runner job',),
 'renew_retry_exhausted':('Lock renewal has run out of retry, stop renew lock for job',),
 'renew_job_invalid':('job is no longer valid, stop renew job request.',),
 'cancel_sent_to_worker':('Send job cancellation message to worker for job ',),
 'runner_shutdown':('The runner has received a shutdown signal.',),
 'os_shutdown':('Operating system is shutting down for computer ',),
 'http_exception':('System.Net.Http.HttpRequestException',),
 'socket_exception':('System.Net.Sockets.SocketException',),
 'null_reference_exception':('System.NullReferenceException',),
}
FIELDS=set('schema source_commit run_id native_outcome runner_version diag_roots_found files_scanned files_unreadable scan_complete signals network_exception_added user_device_tested ready_for_user_apply'.split())
def validate(r):
 if type(r) is not dict or set(r)!=FIELDS or r['schema']!='sstp-runner-signals-1':raise ValueError('schema')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['native_outcome'] not in ['success','failure','cancelled','skipped']:raise ValueError('outcome')
 if r['runner_version'] is not None and not re.fullmatch('[0-9.]{1,40}',r['runner_version']):raise ValueError('version')
 for k,cap in [('diag_roots_found',2),('files_scanned',8),('files_unreadable',8)]:
  if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('count')
 if type(r['scan_complete']) is not bool or set(r['signals'])!=set(SIGNALS):raise ValueError('signals')
 for k in ['network_exception_added','user_device_tested','ready_for_user_apply']:
  if r[k] is not False:raise ValueError('scope')
 for v in r['signals'].values():
  if type(v) is not dict or set(v)!=set(['matches','first_seconds','last_seconds']):raise ValueError('signal_schema')
  if type(v['matches']) is not int or not 0<=v['matches']<=10000:raise ValueError('signal_count')
  for k in ['first_seconds','last_seconds']:
   if v[k] is not None and (type(v[k]) is not int or not 0<=v[k]<=1200):raise ValueError('signal_time')
  if v['matches']==0 and (v['first_seconds'] is not None or v['last_seconds'] is not None):raise ValueError('empty_signal')
  if v['matches']>0 and (v['first_seconds'] is None or v['last_seconds'] is None or v['first_seconds']>v['last_seconds']):raise ValueError('ordered_time')
 return r

def scan(meta,source,run,outcome):
 cutoff=dt.datetime.fromisoformat(meta['cutoff_utc'].replace('Z','+00:00'))
 roots=[Path(x) for x in meta.get('roots',[])][:2]
 version=meta.get('runner_version');version=version if type(version) is str and re.fullmatch('[0-9.]{1,40}',version) else None
 r=dict(schema='sstp-runner-signals-1',source_commit=source,run_id=run,native_outcome=outcome,runner_version=version,diag_roots_found=0,files_scanned=0,files_unreadable=0,scan_complete=True,signals={k:dict(matches=0,first_seconds=None,last_seconds=None) for k in SIGNALS},network_exception_added=False,user_device_tested=False,ready_for_user_apply=False)
 files=[]
 for root in roots:
  if root.is_dir():
   r['diag_roots_found']+=1
   files.extend(root.glob('Runner_*.log'));files.extend(root.glob('Worker_*.log'))
 files=sorted(set(files),key=lambda p:p.stat().st_mtime,reverse=True)
 if len(files)>8:r['scan_complete']=False
 if not files:r['scan_complete']=False
 for p in files[:8]:
  try:
   if p.stat().st_size>32*1024*1024:r['scan_complete']=False;continue
   r['files_scanned']+=1
   with p.open(encoding='utf-8-sig',errors='replace') as f:
    for line in f:
     stamp=re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?Z)',line)
     if not stamp:continue
     at=dt.datetime.fromisoformat(stamp[1].replace('Z','+00:00'));secs=int((at-cutoff).total_seconds())
     if secs<0 or secs>1200:continue
     for key,parts in SIGNALS.items():
      if all(s in line for s in parts):
       v=r['signals'][key]
       if v['matches']>=10000:r['scan_complete']=False;continue
       v['matches']+=1;v['first_seconds']=secs if v['first_seconds'] is None else min(v['first_seconds'],secs);v['last_seconds']=secs if v['last_seconds'] is None else max(v['last_seconds'],secs)
  except (OSError,ValueError):r['files_unreadable']+=1;r['scan_complete']=False
 return validate(r)
def main():
 if len(sys.argv)==4 and sys.argv[1]=='--validate':
  a,b=map(Path,sys.argv[2:]);r=validate(json.loads(a.read_text(encoding='utf-8-sig')))
  if r['source_commit']!=os.environ['EXPECTED_COMMIT'] or r['run_id']!=os.environ['EXPECTED_RUN_ID']:raise ValueError('expected_identity')
  b.parent.mkdir(parents=True,exist_ok=True);b.write_text(json.dumps(r,indent=2)+'\n');return
 if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Windows' or os.environ.get('GITHUB_REPOSITORY')!='kokononox/battle-net-agent-lab':raise ValueError('ci_only')
 meta=Path(os.environ['RUNNER_TEMP'])/'s3u-private-diag-roots.json'
 if meta.exists():m=json.loads(meta.read_text(encoding='utf-8-sig'))
 else:m=dict(roots=[],cutoff_utc=dt.datetime.now(dt.timezone.utc).isoformat(),runner_version=None)
 r=scan(m,os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID'],os.environ.get('NATIVE_OUTCOME','skipped'))
 (Path(__file__).parent/'control-diagnostic.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
