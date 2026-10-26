"""One-shot public index footer ranges only; no full indices/archive/payloads."""
import base64,datetime,hashlib,json,os,re,ssl,stat,urllib.request,urllib.error
from pathlib import Path
from pins import PLAN_SHA256
from footer import verify_footer
from http_contract import NoRedirect,request,read_response
BASE=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;OUT=BASE/'reports/index-footer-g49';PRIVATE=BASE/'private'
class Rejected(ValueError):pass
def sha(b):return hashlib.sha256(b).hexdigest()
def plan(raw):
 if len(raw)>32768 or sha(raw)!=PLAN_SHA256:raise Rejected('plan_pin')
 p=json.loads(raw)
 if p['schema']!='unexecuted_index_footer_range_g48_v1' or p['max_requests']!=16 or len(p['entries'])!=16 or p['expected_application_body_bytes']!=448 or p['max_application_body_read_with_oversize_detection']!=464 or p['executed'] is not False or p['full_index_fetch_approved'] is not False or p['runtime_approved_entries']!=0:raise Rejected('plan_context')
 seen=set()
 for e in p['entries']:
  key=e['expected_index_key'];n=e['expected_content_range_total']
  if not re.fullmatch('[a-f0-9]{32}',key) or e['url']!='https://us.cdn.blizzard.com/tpr/bnt002/data/'+key[:2]+'/'+key[2:4]+'/'+key+'.index':raise Rejected('plan_url')
  if e['id'] in seen or not re.fullmatch('index_[0-9]{1,2}',e['id']) or e['method']!='GET' or e['requested'] is not False or e['runtime_approved'] is not False:raise Rejected('entry_context')
  if type(n) is not int or not 28<n<=131072 or e['range_start']!=n-28 or e['range_end']!=n-1 or e['expected_response_body_bytes']!=28 or e['range_header']!=f'bytes={n-28}-{n-1}':raise Rejected('entry_range')
  seen.add(e['id'])
 return p
def write_new(name,b):
 if not re.fullmatch(r'(session\.started|index_[0-9]{1,2}\.footer\.bin)',name):raise Rejected('private_name')
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
 write_new('session.started',b'16 attempts and 448 expected application bytes reserved before network\n')
 report={'schema':'index_footer_evidence_g49_v1','source_g48_commit':'17ba62931d277d828201c66cdb3bc638ce155396','plan_sha256':PLAN_SHA256,'source_hashes':pre['source_hashes'],'source_head_receipt_sha256':p['source_head_receipt_sha256'],'attempts_reserved':16,'expected_application_body_bytes_reserved':448,'max_application_body_read_with_oversize_detection':464,'not_a_total_wire_or_tls_byte_cap':True,'automatic_retries':0,'redirects_followed':False,'request_body_cookie_authorization_sent':False,'full_index_bodies_requested':False,'archive_or_payload_requested':False,'installer_or_payload_executed':False,'runtime_approved_entries':0,'production_catalog_modified':False,'results':[]}
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
 fixtures={'schema':'public_index_footer_fixtures_g49_v1','contains_payload_or_private_capture':False,'objects':{}}
 for e in p['entries']:
  row={k:e[k] for k in ('id','url','expected_index_key','range_header','expected_content_range_total')};row.update(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),http_status=None,received_and_sized=False,verified=False,error_code=None)
  try:
   try:r=opener.open(request(e),timeout=15)
   except urllib.error.HTTPError as error:r=error
   with r:
    row['http_status']=r.code
    row['observed_content_length']=r.headers.get_all('Content-Length',[]);row['observed_content_range']=r.headers.get_all('Content-Range',[])
    b=read_response(r,e)
   row.update(received_and_sized=True,bytes=len(b),sha256=sha(b));write_new(e['id']+'.footer.bin',b)
   fixtures['objects'][e['id']]={'expected_index_key':e['expected_index_key'],'bytes':len(b),'sha256':sha(b),'base64':base64.b64encode(b).decode()}
   row.update(verify_footer(b,e['expected_index_key'],e['expected_content_range_total']),verified=True)
  except urllib.error.URLError:row['error_code']='tls_or_transport_failed'
  except (ValueError,OSError) as err:
   code=str(err);row['error_code']=code if re.fullmatch('[a-z_0-9]{1,80}',code) else 'footer_verification_or_storage_failed'
  report['results'].append(row)
  (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'public-footer-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
 report['verified_footer_count']=sum(r['verified'] for r in report['results']);report['status']='all_16_footers_verified' if report['verified_footer_count']==16 else 'footer_plan_incomplete'
 (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'received':sum(r['received_and_sized'] for r in report['results']),'verified':report['verified_footer_count'],'errors':[{'id':r['id'],'error':r['error_code']} for r in report['results'] if not r['verified']]}))
if __name__=='__main__':main()
