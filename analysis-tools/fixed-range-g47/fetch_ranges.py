"""Two one-shot research ranges. Never install, execute, or approve runtime traffic."""
import hashlib,json,os,re,ssl,stat,urllib.request,urllib.error
from pathlib import Path
from codec import decode_blte
from pins import PLAN_SHA256
BASE=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
OUT=BASE/'reports/fixed-range-g47';PRIVATE=BASE/'private'
class Rejected(ValueError):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def sha(b):return hashlib.sha256(b).hexdigest()
def load_plan(raw):
 if sha(raw)!=PLAN_SHA256:raise Rejected('plan_pin')
 p=json.loads(raw)
 if p['max_requests']!=2 or len(p['entries'])!=2 or p['expected_encoded_bytes']!=4310 or p['executed'] is not False or p['runtime_approved_entries']!=0:raise Rejected('plan_budget')
 for i,e in enumerate(p['entries'],1):
  key=e['archive_url'].rsplit('/',1)[-1]
  if not re.fullmatch('[a-f0-9]{32}',key) or e['archive_url']!='https://us.cdn.blizzard.com/tpr/bnt002/data/'+key[:2]+'/'+key[2:4]+'/'+key:raise Rejected('plan_url')
  if e['sample_id']!='sample_'+str(i) or e['range_end']-e['range_start']+1!=e['expected_encoded_bytes'] or e['range_header']!=f"bytes={e['range_start']}-{e['range_end']}":raise Rejected('plan_range')
  if not 0<e['expected_encoded_bytes']<=8192 or not 0<e['expected_decoded_bytes']<=65536 or e['runtime_approved'] is not False:raise Rejected('plan_bounds')
 return p
def request(e):
 return urllib.request.Request(e['archive_url'],method='GET',headers={'User-Agent':'BattleNetFixedRangeReview/0.1','Accept':'application/octet-stream','Accept-Encoding':'identity','Connection':'close','Range':e['range_header']})
def read_response(r,e):
 if r.code!=206:raise Rejected('http_status_'+str(r.code))
 h=r.headers
 def one(name,required=False):
  values=h.get_all(name,[])
  if len(values)>1 or required and len(values)!=1:raise Rejected('response_header_cardinality')
  return values[0] if values else None
 length=one('Content-Length',True);cr=one('Content-Range',True);ce=one('Content-Encoding');te=one('Transfer-Encoding')
 if te is not None or ce is not None and ce.lower()!='identity':raise Rejected('response_encoding_or_transfer')
 if not length.isdigit() or int(length)!=e['expected_encoded_bytes']:raise Rejected('response_length')
 m=re.fullmatch(r'bytes ([0-9]+)-([0-9]+)/([0-9]+)',cr)
 if not m:raise Rejected('content_range_syntax')
 start,end,total=map(int,m.groups())
 if start!=e['range_start'] or end!=e['range_end'] or total<=end:raise Rejected('content_range_mismatch')
 data=bytearray();bound=e['expected_encoded_bytes']
 while len(data)<=bound:
  c=r.read(min(4096,bound+1-len(data)))
  if not c:break
  data.extend(c)
 if len(data)!=bound:raise Rejected('response_size')
 return bytes(data)
def verify(e,b):
 if len(b)!=e['expected_encoded_bytes']:raise Rejected('encoded_size')
 d=decode_blte(b,e['expected_decoded_bytes'],e['ekey'])
 if hashlib.md5(d).hexdigest()!=e['ckey']:raise Rejected('decoded_ckey')
 return {'encoded_sha256':sha(b),'decoded_sha256':sha(d),'encoded_bytes':len(b),'decoded_bytes':len(d),'blte_ekey_verified':True,'decoded_ckey_verified':True,'decoded_starts_with_mz':d.startswith(b'MZ')},d
def save(name,data):
 if not re.fullmatch(r'(session\.started|sample_[12]\.(encoded|decoded)\.bin)',name):raise Rejected('private_name')
 fd=os.open(PRIVATE/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def main():
 plan=load_plan((HERE/'plan.review-only.json').read_bytes());pre=json.loads((OUT/'preflight.json').read_text())
 if sha(Path(__file__).read_bytes())!=pre['fetch_source_sha256'] or sha((HERE/'codec.py').read_bytes())!=pre['codec_sha256'] or pre['plan_sha256']!=PLAN_SHA256 or not pre['offline_tests_passed']:raise Rejected('preflight_binding')
 if os.name!='posix':raise Rejected('research_posix_only')
 PRIVATE.mkdir(mode=0o700,exist_ok=True);s=PRIVATE.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid!=os.getuid():raise Rejected('private_directory')
 save('session.started',b'two_attempts_and_4310_expected_bytes_reserved_before_network\n')
 report={'schema':'fixed_range_evidence_g47_v1','source_g46_commit':'e4153a9ee5094d66d5ccc821cb69f99738da8886','plan_sha256':PLAN_SHA256,'source_sha256':pre['fetch_source_sha256'],'codec_sha256':pre['codec_sha256'],'reserved_attempts':2,'reserved_expected_bytes':4310,'max_application_body_read_bytes_with_oversize_detection':4312,'not_a_total_wire_or_tls_byte_cap':True,'automatic_retries':0,'redirects_followed':False,'request_body_sent':False,'cookies_or_authorization_sent':False,'runtime_approved_entries':0,'installer_or_payload_executed':False,'production_catalog_modified':False,'publisher_signature_verified':False,'anti_fingerprinting_proven':False,'results':[]}
 context=ssl.create_default_context();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context))
 for e in plan['entries']:
  row={k:e[k] for k in ('sample_id','archive_url','range_header','expected_encoded_bytes','expected_decoded_bytes','ekey','ckey','source_index_id','source_index_sha256')};row.update(http_status=None,body_received_and_sized=False,verified=False,error_code=None,runtime_approved=False)
  try:
   try:r=opener.open(request(e),timeout=25)
   except urllib.error.HTTPError as error:r=error
   with r:
    row['http_status']=r.code
    row['observed_content_length']=r.headers.get_all('Content-Length',[]);row['observed_content_range']=r.headers.get_all('Content-Range',[])
    b=read_response(r,e)
   row.update(body_received_and_sized=True,received_bytes=len(b),received_sha256=sha(b));save(e['sample_id']+'.encoded.bin',b)
   v,d=verify(e,b);save(e['sample_id']+'.decoded.bin',d);row.update(v,verified=True,stored_private_non_executable=True)
  except urllib.error.URLError:row['error_code']='tls_or_transport_failed'
  except (ValueError,OSError) as error:
   code=str(error);row['error_code']=code if re.fullmatch('[a-z_0-9]{1,80}',code) else 'verification_or_storage_failed'
  report['results'].append(row)
  (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 report['verified_payload_count']=sum(x['verified'] for x in report['results']);report['status']='two_range_samples_verified' if report['verified_payload_count']==2 else 'range_plan_incomplete'
 (OUT/'fetch-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
