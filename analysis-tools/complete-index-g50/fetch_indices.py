"""One-shot 16 footer-bound public metadata GETs; no archive/payload fetch."""
import base64,datetime,hashlib,json,os,re,ssl,stat,urllib.request,urllib.error
from pathlib import Path
from pins import PLAN_SHA256
from index_parser import parse_index
from http_contract import NoRedirect,request,read_response
BASE=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;OUT=BASE/'reports/complete-index-g50';PRIVATE=BASE/'private'
class Rejected(ValueError):pass
def sha(b):return hashlib.sha256(b).hexdigest()
def plan(raw):
 if len(raw)>32768 or sha(raw)!=PLAN_SHA256:raise Rejected('plan_pin')
 p=json.loads(raw)
 if p['schema']!='unexecuted_footer_bound_full_index_plan_g49_v1' or p['max_requests']!=16 or len(p['entries'])!=16 or p['expected_application_body_bytes']!=272368 or p['max_application_body_read_with_oversize_detection']!=272384 or p['executed'] is not False or p['payload_or_archive_fetch_approved'] is not False or p['runtime_approved_entries']!=0:raise Rejected('plan_context')
 seen=set()
 for e in p['entries']:
  k=e['archive_or_index_key']
  if not re.fullmatch('[a-f0-9]{32}',k) or e['url']!='https://us.cdn.blizzard.com/tpr/bnt002/data/'+k[:2]+'/'+k[2:4]+'/'+k+'.index':raise Rejected('plan_url')
  if e['id'] in seen or not re.fullmatch('index_[0-9]{1,2}',e['id']) or e['kind']!='archive_index' or e['method']!='GET' or e['requested'] is not False or e['runtime_approved'] is not False or e['source_footer_id']!=e['id']:raise Rejected('entry_context')
  if type(e['expected_bytes']) is not int or not 28<e['expected_bytes']<=131072 or not re.fullmatch('[a-f0-9]{64}',e['expected_footer_sha256']):raise Rejected('entry_bounds')
  seen.add(e['id'])
 if sum(e['expected_bytes'] for e in p['entries'])!=272368:raise Rejected('plan_budget')
 return p
def verify(e,b):
 if len(b)!=e['expected_bytes'] or sha(b[-28:])!=e['expected_footer_sha256']:raise Rejected('prior_footer_binding')
 return parse_index(b,e['archive_or_index_key'],e['kind'])
def save(name,b):
 if not re.fullmatch(r'(session\.started|index_[0-9]{1,2}\.bin)',name):raise Rejected('private_name')
 fd=os.open(PRIVATE/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def main():
 p=plan((HERE/'plan.review-only.json').read_bytes());pre=json.loads((OUT/'preflight.json').read_text())
 if pre['plan_sha256']!=PLAN_SHA256 or pre['offline_tests_passed'] is not True:raise Rejected('preflight_binding')
 for name,digest in pre['source_hashes'].items():
  if sha((HERE/name).read_bytes())!=digest:raise Rejected('source_binding')
 if os.name!='posix':raise Rejected('research_posix_only')
 PRIVATE.mkdir(mode=0o700,exist_ok=True);s=PRIVATE.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid!=os.getuid():raise Rejected('private_directory')
 save('session.started',b'16 attempts and 272368 expected bytes reserved before network\n')
 report={'schema':'complete_index_fetch_g50_v1','source_g49_commit':'d4fa2476f43f955ba4d52dc0e04d2898d075d57b','plan_sha256':PLAN_SHA256,'source_hashes':pre['source_hashes'],'attempts_reserved':16,'expected_application_body_bytes_reserved':272368,'max_application_body_read_with_oversize_detection':272384,'not_a_total_wire_or_tls_byte_cap':True,'automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'range_requests_issued':False,'archive_or_payload_requested':False,'installer_or_payload_executed':False,'runtime_approved_entries':0,'production_catalog_modified':False,'results':[]}
 fixtures={'schema':'public_complete_index_fixtures_g50_v1','contains_payload_or_private_capture':False,'objects':{}}
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
 for e in p['entries']:
  row={k:e[k] for k in ('id','url','kind','archive_or_index_key','expected_bytes','expected_footer_sha256')};row.update(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),http_status=None,received_and_sized=False,verified=False,error_code=None)
  try:
   try:r=opener.open(request(e),timeout=15)
   except urllib.error.HTTPError as error:r=error
   with r:
    row['http_status']=r.code;row['observed_content_length']=r.headers.get_all('Content-Length',[]);b=read_response(r,e['expected_bytes'])
   row.update(received_and_sized=True,bytes=len(b),sha256=sha(b));save(e['id']+'.bin',b)
   fixtures['objects'][e['id']]={'key':e['archive_or_index_key'],'kind':e['kind'],'bytes':len(b),'sha256':sha(b),'base64':base64.b64encode(b).decode()}
   pindex=verify(e,b);row.update(verified=True,record_count=pindex['entry_count'],blocks_verified=len(pindex['blocks']),prior_footer_sha256_matches=True,toc_and_all_blocks_verified=True)
  except urllib.error.URLError:row['error_code']='tls_or_transport_failed'
  except (ValueError,OSError) as err:
   code=str(err);row['error_code']=code if re.fullmatch('[a-z_0-9]{1,80}',code) else 'index_verification_or_storage_failed'
  report['results'].append(row)
  (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'public-index-fixtures.json').write_text(json.dumps(fixtures,separators=(',',':'))+'\n')
 report['verified_index_count']=sum(r['verified'] for r in report['results']);report['status']='all_16_full_indexes_verified' if report['verified_index_count']==16 else 'index_plan_incomplete'
 (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'received':sum(r['received_and_sized'] for r in report['results']),'verified':report['verified_index_count'],'errors':[{'id':r['id'],'error':r['error_code']} for r in report['results'] if not r['verified']]}))
if __name__=='__main__':main()
