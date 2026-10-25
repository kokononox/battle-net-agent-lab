"""Fixed public metadata requests. No client relay, identifier, login or execution."""
import datetime,hashlib,json,re,ssl,urllib.request,urllib.error,urllib.parse
from pathlib import Path
BASE=Path(__file__).resolve().parents[2];RAW=BASE/'public-metadata';OUT=BASE/'reports/public-manifest-g43'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
HOSTS={'us.version.battle.net'}
def request(url,label,limit=262144):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='https' or p.hostname not in HOSTS or p.port not in (None,443) or p.username or p.password or p.query or p.fragment or not re.fullmatch(r'/[A-Za-z0-9/_.-]+',p.path):raise ValueError('url_rejected')
 if not re.fullmatch('[a-z0-9-]+',label):raise ValueError('label_rejected')
 r={'url':url,'method':'GET','query_present':False,'application_body_sent':False,'cookie_sent':False,'redirects_followed':False}
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'BattleNetPublicManifestReview/0.1','Accept':'text/plain, application/octet-stream','Accept-Encoding':'identity'})
  try:response=OPENER.open(req,timeout=25)
  except urllib.error.HTTPError as e:response=e
  with response:
   r['status']=response.code
   if response.code!=200:r['accepted']=False;return r,None
   if response.headers.get('Content-Encoding','identity').lower()!='identity':raise ValueError('encoding_rejected')
   length=response.headers.get('Content-Length')
   if length is not None and (not length.isdigit() or int(length)>limit):raise ValueError('length_rejected')
   blob=response.read(limit+1)
   if len(blob)>limit or length is not None and int(length)!=len(blob):raise ValueError('size_rejected')
   r.update(accepted=True,bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest(),content_type=response.headers.get('Content-Type'))
   path=RAW/(label+'.bin')
   if path.exists():raise ValueError('snapshot_exists_no_overwrite')
   path.write_bytes(blob);r['snapshot']=str(path.relative_to(BASE));return r,blob
 except urllib.error.URLError:r.update(accepted=False,error_code='tls_or_transport_failed')
 except (OSError,ValueError) as e:r.update(accepted=False,error_code=str(e) if isinstance(e,ValueError) else 'transport_read_failed')
 return r,None

def psv(blob):
 if len(blob)>262144:raise ValueError('psv_size_bound')
 s=blob.decode('utf-8-sig');lines=[line for line in s.splitlines() if line and not line.startswith('#')]
 if not lines or len(lines)>2049:raise ValueError('psv_row_bound')
 header=lines[0].split('|')
 if len(header)>64 or any(not re.fullmatch('[A-Za-z][A-Za-z0-9_]*![A-Za-z]+:[0-9]+',c) for c in header):raise ValueError('psv_header')
 names=[c.split('!')[0] for c in header]
 if len(set(names))!=len(names):raise ValueError('psv_duplicate_column')
 rows=[]
 for line in lines[1:]:
  cells=line.split('|')
  if len(cells)!=len(names) or any(len(c)>16384 or any(ord(x)<32 for x in c) for c in cells):raise ValueError('psv_row')
  rows.append(dict(zip(names,cells)))
 return {'columns':names,'rows':rows}

def main():
 records=[];parsed={}
 # v1 format from public docs; v2 API shape is independently visible on official service.
 for variant,prefix in [('v1','/bna'),('v2','/v2/products/bna')]:
  for typ in ('versions','cdns'):
   row,blob=request('https://us.version.battle.net'+prefix+'/'+typ,variant+'-'+typ);records.append(row)
   if blob is not None:
    try:parsed[variant+'-'+typ]=psv(blob)
    except (ValueError,UnicodeError):row.update(accepted=False,error_code='psv_parse_failed')
  if all(variant+'-'+t in parsed for t in ('versions','cdns')):break
 e={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'schema':'public_manifest_discovery_g43_v1','requests':records,'parsed':parsed,'installer_executed':False,'payload_downloaded':False,'runtime_network_policy_changed':False,'catalog_entries_approved':0,'telemetry_endpoint_requested':False}
 (OUT/'discovery.json').write_text(json.dumps(e,indent=2)+'\n')
 print(json.dumps({'requests':records,'parsed':parsed}))
if __name__=='__main__':main()
