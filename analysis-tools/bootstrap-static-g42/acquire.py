"""Bounded official bootstrap acquisition. Never executes downloaded bytes."""
import datetime,hashlib,json,os,re,urllib.request,urllib.error,urllib.parse
from pathlib import Path
BASE=Path(__file__).resolve().parents[2];OUT=BASE/'private';REPORT=BASE/'reports/bootstrap-static-g42'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
ALLOWED={'download.battle.net','downloader.battle.net'}
def fetch(url,maximum):
 route=[]
 for _ in range(5):
  p=urllib.parse.urlsplit(url)
  if p.scheme!='https' or p.hostname not in ALLOWED or p.port not in (None,443) or p.username or p.password or p.fragment:raise ValueError('route_rejected')
  req=urllib.request.Request(url,headers={'User-Agent':'BattleNetStaticResourceReview/0.1','Accept':'*/*','Accept-Encoding':'identity'})
  try:r=opener.open(req,timeout=30)
  except urllib.error.HTTPError as e:r=e
  with r:
   row={'url':url,'method':'GET','status':r.code};route.append(row)
   if r.code in (301,302,303,307,308):
    location=r.headers.get('Location')
    if not location:raise ValueError('redirect_without_location')
    url=urllib.parse.urljoin(url,location);row['location']=url;continue
   if r.code!=200:raise ValueError('status_rejected')
   if r.headers.get('Content-Encoding','identity').lower()!='identity':raise ValueError('encoding_rejected')
   declared=r.headers.get('Content-Length')
   if declared is not None and (not declared.isdigit() or int(declared)>maximum):raise ValueError('length_rejected')
   data=r.read(maximum+1)
   if len(data)>maximum or declared is not None and len(data)!=int(declared):raise ValueError('size_rejected')
   for k in ('Content-Length','Content-Type','ETag','Last-Modified'):
    if r.headers.get(k):row[k.lower()]=r.headers[k]
   return data,route
 raise ValueError('redirect_limit')
page,page_route=fetch('https://download.battle.net/en-us/?platform=windows',4*1024*1024)
text=page.decode('utf-8','strict');url='https://downloader.battle.net//download/getInstallerForGame?os=win&gameProgram=BATTLENET_APP&version=Live'
# Only the exact current official Windows URL is accepted, not arbitrary links.
if url not in text and url.replace('&','&amp;') not in text:raise ValueError('official_link_not_present')
blob,route=fetch(url,32*1024*1024)
if blob[:2]!=b'MZ':raise ValueError('not_pe_bootstrap')
OUT.mkdir(parents=True,exist_ok=True);f=OUT/'Battle.net-Setup.exe';fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as w:w.write(blob)
e={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_page_route':page_route,'exact_windows_link_present':True,'installer_route':route,'bytes':len(blob),'sha256':hashlib.sha256(blob).hexdigest(),'historical_pin_sha256':'f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6','historical_pin_matches':hashlib.sha256(blob).hexdigest()=='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6','installer_executed':False,'payload_executed':False,'authenticode_trust_verified':False,'runtime_network_policy_changed':False,'catalog_entries_approved':0}
(REPORT/'acquisition.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e))
