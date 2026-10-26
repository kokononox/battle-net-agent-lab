"""One-shot 16 fixed HEAD observations. Never read response bodies or retry GET."""
import datetime,hashlib,json,os,re,ssl,stat,urllib.request,urllib.error
from pathlib import Path
from pins import PLAN_SHA256
BASE=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;OUT=BASE/'reports/index-head-g48';PRIVATE=BASE/'private'
class Rejected(ValueError):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def sha(b):return hashlib.sha256(b).hexdigest()
def plan(raw):
 if len(raw)>32768 or sha(raw)!=PLAN_SHA256:raise Rejected('plan_pin')
 p=json.loads(raw)
 if p['max_requests']!=16 or len(p['entries'])!=16 or p['method']!='HEAD' or p['request_body'] is not None or p['response_body_read_budget']!=0 or p['executed'] is not False or p['automatic_redirects'] is not False or p['automatic_retries']!=0:raise Rejected('plan_context')
 seen=set()
 for e in p['entries']:
  m=re.fullmatch(r'https://us\.cdn\.blizzard\.com/tpr/bnt002/data/([a-f0-9]{2})/([a-f0-9]{2})/([a-f0-9]{32})\.index',e['url'])
  if not m or m[1]!=m[3][:2] or m[2]!=m[3][2:4] or e['id'] in seen or e['requested'] is not False or e['original_actual_content_length'] is not None:raise Rejected('entry_context')
  seen.add(e['id'])
 return p
def request(e):
 return urllib.request.Request(e['url'],method='HEAD',headers={'User-Agent':'BattleNetFixedIndexHeadReview/0.1','Accept':'application/octet-stream','Accept-Encoding':'identity','Connection':'close'})
def observe(response,e):
 # Header allowlist only. Intentionally never call read(), even on error/redirect.
 headers={}
 for name in ('Content-Length','Content-Encoding','Transfer-Encoding','Content-Range','Content-Type','Accept-Ranges'):
  vals=response.headers.get_all(name,[])
  if len(vals)>4 or any(len(v)>256 or any(ord(c)<32 or ord(c)>126 for c in v) for v in vals):raise Rejected('header_record_bounds')
  headers[name.lower()]=vals
 lengths=headers['content-length'];n=None
 if len(lengths)==1 and re.fullmatch('[0-9]{1,15}',lengths[0]):n=int(lengths[0])
 valid=response.code==200 and n is not None and not headers['content-range'] and not headers['transfer-encoding'] and headers['content-encoding'] in ([],['identity'])
 return {'http_status':response.code,'observed_headers':headers,'advertised_content_length':n,'head_length_usable_for_review':valid,'matches_original_expected':n==e['original_expected_bytes'] if valid else None,'body_read_calls':0,'payload_or_index_validated':False}
def run():
 p=plan((HERE/'plan.review-only.json').read_bytes());pre=json.loads((OUT/'preflight.json').read_text())
 if pre['source_sha256']!=sha(Path(__file__).read_bytes()) or pre['plan_sha256']!=PLAN_SHA256 or pre['offline_tests_passed'] is not True:raise Rejected('preflight_binding')
 if os.name!='posix':raise Rejected('research_posix_only')
 PRIVATE.mkdir(mode=0o700,exist_ok=True);s=PRIVATE.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid!=os.getuid():raise Rejected('private_directory')
 fd=os.open(PRIVATE/'session.started',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w') as f:f.write('16 HEAD attempts reserved before network; zero response body reads\n');f.flush();os.fsync(f.fileno())
 report={'schema':'fixed_head_evidence_g48_v1','source_g46_commit':'e4153a9ee5094d66d5ccc821cb69f99738da8886','source_sha256':pre['source_sha256'],'plan_sha256':PLAN_SHA256,'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'attempts_reserved':16,'response_body_read_calls':0,'response_body_read_budget':0,'total_tls_or_wire_bytes_metered':False,'request_method':'HEAD','automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'get_requests_issued':False,'range_requests_issued':False,'installer_or_payload_executed':False,'runtime_approved_entries':0,'production_catalog_modified':False,'results':[]}
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
 for e in p['entries']:
  r={'id':e['id'],'url':e['url'],'original_expected_bytes':e['original_expected_bytes'],'original_g46_actual_content_length':None,'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'error_code':None}
  try:
   try:response=opener.open(request(e),timeout=15)
   except urllib.error.HTTPError as error:response=error
   with response:r.update(observe(response,e))
  except urllib.error.URLError:r['error_code']='tls_or_transport_failed'
  except (ValueError,OSError) as err:
   code=str(err);r['error_code']=code if re.fullmatch('[a-z_0-9]{1,80}',code) else 'header_observation_failed'
  report['results'].append(r);(OUT/'head-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 report['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();(OUT/'head-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'attempts':len(report['results']),'observed_statuses':[r.get('http_status') for r in report['results']],'body_read_calls':0}))
if __name__=='__main__':run()
