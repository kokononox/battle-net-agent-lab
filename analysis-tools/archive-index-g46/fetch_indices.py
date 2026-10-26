"""One-shot fixed metadata-only fetch. No archives, Range, executable loading or retry."""
import hashlib,json,os,re,ssl,stat,urllib.request,urllib.error
from pathlib import Path
from http_contract import NoRedirect,read_response,Rejected
from pins import PLAN_SHA256
BASE=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
STORE=BASE/'public-indices';REPORT=BASE/'reports/archive-index-g46'
def plan(raw):
 if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=PLAN_SHA256:raise Rejected('plan_pin')
 p=json.loads(raw)
 if p['schema']!='proposed_metadata_index_plan_g45_v1' or p['executed'] is not False or p['max_requests']!=46 or len(p['entries'])!=46 or p['expected_application_body_bytes']!=623408:raise Rejected('plan_context')
 seen=set()
 for i,e in enumerate(p['entries']):
  k=e['archive_or_index_key']
  if e['id']!='index_'+str(i+1) or not re.fullmatch('[a-f0-9]{32}',k) or k in seen:raise Rejected('entry_identity')
  seen.add(k)
  if type(e['expected_bytes']) is not int or not 0<e['expected_bytes']<=131072:raise Rejected('entry_size')
  if e['kind']!=('archive_index' if i<45 else 'loose_file_index') or e['requested'] is not False or e['runtime_approved'] is not False:raise Rejected('entry_context')
  if e['proposed_url']!='https://us.cdn.blizzard.com/tpr/bnt002/data/'+k[:2]+'/'+k[2:4]+'/'+k+'.index':raise Rejected('entry_url')
 if sum(e['expected_bytes'] for e in p['entries'])!=p['expected_application_body_bytes']:raise Rejected('plan_budget')
 return p

def make_request(e):
 return urllib.request.Request(e['proposed_url'],method='GET',headers={'User-Agent':'BattleNetFixedIndexReview/0.1','Accept':'application/octet-stream','Accept-Encoding':'identity','Connection':'close'})
def secure_store():
 if os.name!='posix':raise Rejected('research_posix_only')
 STORE.mkdir(parents=True,mode=0o700,exist_ok=True);s=STORE.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid!=os.getuid():raise Rejected('store_permissions')
def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def run():
 raw=(HERE/'index-plan.review-only.json').read_bytes();p=plan(raw);secure_store();write_new(STORE/'session.started',b'reserved before network\n')
 ctx=ssl.create_default_context();op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ctx))
 r={'schema':'public_indices_fetch_g46_v1','source_plan_commit':'31cc1850591ddc381eca486fa10d51be2b6c1157','plan_sha256':PLAN_SHA256,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'max_requests':46,'expected_application_body_budget':623408,'max_application_body_read_with_oversize_detection':623454,'reserved_attempts':0,'reserved_expected_bytes':0,'results':[],'archive_bodies_requested':False,'range_requests_issued':False,'installer_or_payload_executed':False,'runtime_approved_entries':0,'production_catalog_modified':False,'automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'tls_or_total_wire_bytes_metered':False}
 for e in p['entries']:
  r['reserved_attempts']+=1;r['reserved_expected_bytes']+=e['expected_bytes']
  if r['reserved_attempts']>46 or r['reserved_expected_bytes']>623408:raise Rejected('budget_exceeded')
  row={'id':e['id'],'kind':e['kind'],'archive_or_index_key':e['archive_or_index_key'],'url':e['proposed_url'],'expected_bytes':e['expected_bytes'],'http_status':None,'received_and_sized':False,'error_code':None,'parsed_or_authenticated':False}
  try:
   try:response=op.open(make_request(e),timeout=15)
   except urllib.error.HTTPError as error:response=error
   with response:row['http_status']=response.code;data=read_response(response,e['expected_bytes'])
   path=STORE/(e['id']+'.bin');write_new(path,data)
   row.update(received_and_sized=True,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),snapshot_name=path.name)
  except urllib.error.URLError:row['error_code']='tls_or_transport_failed'
  except (ValueError,OSError) as error:
   code=str(error);row['error_code']=code if re.fullmatch('[a-z_0-9]{1,80}',code) else 'metadata_read_or_storage_failed'
  r['results'].append(row)
  # Receipt survives later transport failure without retrying spent attempts.
  (REPORT/'fetch-progress.local.json').write_text(json.dumps(r,indent=2)+'\n')
 r['status']='all_fixed_indices_received' if all(x['received_and_sized'] for x in r['results']) else 'index_fetch_incomplete'
 (REPORT/'fetch-evidence.json').write_text(json.dumps(r,indent=2)+'\n')
 print(json.dumps({'status':r['status'],'attempts':r['reserved_attempts'],'received':sum(x['received_and_sized'] for x in r['results']),'errors':[{'id':x['id'],'error':x['error_code'],'status':x['http_status']} for x in r['results'] if not x['received_and_sized']]}))
 return r['status']=='all_fixed_indices_received'
if __name__=='__main__':raise SystemExit(0 if run() else 2)
