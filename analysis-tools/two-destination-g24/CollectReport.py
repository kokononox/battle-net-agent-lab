"""Separate clean Linux job: recover sanitized report; never publish raw VM logs."""
import base64,hashlib,io,json,os,re,sys,time,urllib.request,urllib.error,zipfile,zlib
from pathlib import Path
MAX_LOG=8*1024*1024;MAX_REPORT=131072
FIELDS={'certificate_preparation','all_processes_observed','all_target_egress_blocked_proven','ambient_drift_did_not_waive_recovery','bits','classification','classifier_live_tests','classifier_unit_tests','components','driver','external_brokers_auto_enrolled','files_evidence','full_chain_discovered','game_download_requested','https_payload_classified','install_options_action_requested','installation_verified','installer_launched','login_attempted','minimum_two_destinations_tested','online_preflight','owner','owner_error_code','owner_failure_diagnostic','owner_failure_proof','preflight','proxy_event_counts','proxy_drain','installer_error_codes','windows_tls_events','recovery','recovery_error_shape','recovery_gate_tests','registration_changes_by_kind','registration_diff_complete','registration_differences','request_metadata','run_id','scenario','schema','source_commit','status','svc_trust','system_baseline','system_prelaunch','tls_scope','ui'}
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('duplicate_json_key')
  d[k]=v
 return d

def validate(d,sha,run):
 if type(d)!=dict or not set(d)<=FIELDS or d.get('schema')!='two_destination_setup_g24_v1' or d.get('source_commit')!=sha or d.get('run_id')!=run or d.get('scenario')!='real_setup':raise ValueError('report_identity_or_fields')
 if d.get('installation_verified') is not False or d.get('https_payload_classified') is not False:raise ValueError('unsupported_report_claim')
 def walk(v,depth=0):
  if depth>12:raise ValueError('report_depth')
  if v is None or type(v) in (bool,int):return
  if type(v)==str:
   if len(v)>180 or not re.fullmatch(r'[A-Za-z0-9_.:/\[\] ,+()=-]*',v):raise ValueError('report_string')
  elif type(v)==list:
   if len(v)>256:raise ValueError('report_array')
   for x in v:walk(x,depth+1)
  elif type(v)==dict:
   if len(v)>256:raise ValueError('report_object')
   for k,x in v.items():walk(k,depth+1);walk(x,depth+1)
  else:raise ValueError('report_value')
 walk(d);return d

def extract(text,sha,run):
 manifests=list(re.finditer(r'G24_REPORT_MANIFEST (\{[^\r\n]+\})',text));verified=[]
 for i,m in enumerate(manifests):
  try:
   meta=json.loads(m.group(1),object_pairs_hook=unique)
   if set(meta)!={'parts','raw_bytes','sha256'} or type(meta['parts'])!=int or not 1<=meta['parts']<=128 or type(meta['raw_bytes'])!=int or not 0<meta['raw_bytes']<=MAX_REPORT or not re.fullmatch('[a-f0-9]{64}',meta['sha256']):continue
   block=text[m.end():manifests[i+1].start() if i+1<len(manifests) else len(text)]
   rows=re.findall(r'G24_REPORT_PART (\d+)/(\d+) ([A-Za-z0-9+/=]+)',block)
   if len(rows)!=meta['parts'] or [int(x[0]) for x in rows]!=list(range(1,meta['parts']+1)) or any(int(x[1])!=meta['parts'] or len(x[2])>600 for x in rows):continue
   packed=base64.b64decode(''.join(x[2] for x in rows),validate=True);decoder=zlib.decompressobj();raw=decoder.decompress(packed,MAX_REPORT+1)
   if len(raw)!=meta['raw_bytes'] or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=meta['sha256']:continue
   report=validate(json.loads(raw,object_pairs_hook=unique),sha,run);verified.append((raw,report,meta))
  except (ValueError,TypeError,KeyError,zlib.error):continue
 if not verified:raise ValueError('no_verified_report')
 return verified[-1]

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None

def api(path,token,binary=False):
 if not path.startswith('/repos/kokononox/battle-net-agent-lab/'):raise ValueError('api_scope')
 req=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','User-Agent':'g24-clean-report-collector'})
 try:
  with urllib.request.build_opener(NoRedirect()).open(req,timeout=25) as r:data=r.read(MAX_LOG+1)
 except urllib.error.HTTPError as e:
  if not binary or e.code!=302:raise
  url=e.headers.get('Location','');from urllib.parse import urlparse
  parsed=urlparse(url)
  if parsed.scheme!='https' or not parsed.hostname or not parsed.hostname.endswith('.blob.core.windows.net'):raise ValueError('log_redirect_scope')
  # Separate request: never send Authorization to the signed blob URL.
  with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url,headers={'User-Agent':'g24-clean-report-collector'}),timeout=25) as r:data=r.read(MAX_LOG+1)
 if len(data)>MAX_LOG:raise ValueError('log_size_limit')
 return data if binary else json.loads(data)

def main():
 if os.getenv('RUNNER_OS')!='Linux' or os.getenv('RUNNER_ENVIRONMENT')!='github-hosted' or os.getenv('GITHUB_REPOSITORY')!='kokononox/battle-net-agent-lab':raise ValueError('clean_hosted_job_required')
 sha=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID'];token=os.environ['GH_REPORT_TOKEN'];prefix='/repos/kokononox/battle-net-agent-lab';out=Path('collected');out.mkdir(exist_ok=True)
 run_info=api(prefix+'/actions/runs/'+run,token)
 if run_info.get('head_sha')!=sha or run_info.get('head_branch')!='research/battlenet-minimal-install-isolation-2026-10-25' or run_info.get('run_attempt')!=1:raise ValueError('run_identity')
 jobs=api(prefix+'/actions/runs/'+run+'/jobs?per_page=100',token);candidates=[j for j in jobs.get('jobs',[]) if j.get('name')=='observe (real_setup)' and j.get('status')=='completed']
 if len(candidates)!=1:raise ValueError('job_identity')
 job=candidates[0];raw_logs=None
 for n in range(4):
  try:raw_logs=api(prefix+'/actions/jobs/'+str(job['id'])+'/logs',token,True);break
  except urllib.error.HTTPError as e:
   if e.code not in {404,410} or n==3:raise
   time.sleep(5)
 if raw_logs.startswith(b'PK'):
  with zipfile.ZipFile(io.BytesIO(raw_logs)) as z:
   entries=[x for x in z.infolist() if not x.is_dir() and x.filename.endswith('.txt')]
   if len(entries)>32 or sum(x.file_size for x in entries)>MAX_LOG:raise ValueError('archive_bounds')
   text='\n'.join(z.read(x).decode('utf-8',errors='replace') for x in entries)
 else:text=raw_logs.decode('utf-8',errors='replace')
 raw,report,manifest=extract(text,sha,run)
 (out/'online-g24.json').write_bytes(raw)
 proof={'source_commit':sha,'run_id':run,'job_id':job['id'],'job_conclusion':job.get('conclusion'),'manifest':manifest,'verified':True,'report_status':report['status']}
 (out/'provenance.json').write_text(json.dumps(proof,indent=2))
 print(json.dumps(proof));print('Sanitized evidence recovered. Raw logs are not written or uploaded.')
if __name__=='__main__':
 try:main()
 except Exception as e:
  # No exception repr: HTTP URLs may contain signed credentials.
  print('G24_COLLECTION_FAILED '+(str(e) if type(e)==ValueError and re.fullmatch('[a-z_]{1,80}',str(e)) else type(e).__name__))
  raise SystemExit(1)
