"""Publish one strict minimal CI receipt in clean reporting job, no raw logs."""
import base64,json,os,re,urllib.request,urllib.error
from pathlib import Path
from run_portable_ci import MODULES
REPO='kokononox/battle-net-agent-lab'
PATH='reports/updater-portable-windows-latest.json'
def validate(raw,commit):
 assert type(raw)is bytes and 0<len(raw)<=16384
 def pairs(rows):
  d={}
  for k,v in rows:assert k not in d;d[k]=v
  return d
 r=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))
 keys={'format','source_commit','platform','python_version','tests_run','failures','errors','skipped','passed','test_modules','scope','game_access','network_in_test_suite','native_windows_staging_backend_qualified','windows_installer_qualified','installation_ready','apply_authorized'}
 assert type(r)is dict and set(r)==keys and r['format']=='updater-portable-offline-ci-1'and re.fullmatch('[0-9a-f]{40}',commit)and r['source_commit']==commit
 assert r['platform']=='Windows'and type(r['python_version'])is str and re.fullmatch('[0-9]+\.[0-9]+\.[0-9]+',r['python_version'])
 assert r['scope']=='synthetic_stream_parser_and_selection_only'and r['test_modules']==MODULES
 for k in ['tests_run','failures','errors','skipped']:assert type(r[k])is int and 0<=r[k]<=1000
 assert r['tests_run']==73 and r['failures']==r['errors']==r['skipped']==0 and r['passed']is True
 for k in ['game_access','network_in_test_suite','native_windows_staging_backend_qualified','windows_installer_qualified','installation_ready','apply_authorized']:assert r[k]is False
 return r

def publish():
 assert os.environ['GITHUB_REPOSITORY']==REPO
 commit=os.environ['UPDATER_SOURCE_COMMIT'];r=validate(Path('incoming/updater-portable-windows-to-share.json').read_bytes(),commit);token=os.environ['GITHUB_TOKEN'];url='https://api.github.com/repos/'+REPO+'/contents/'+PATH
 def request(method,data=None):
  req=urllib.request.Request(url,data=None if data is None else json.dumps(data).encode(),method=method,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json','User-Agent':'bounded-updater-offline-ci'})
  with urllib.request.urlopen(req,timeout=30)as response:
   raw=response.read(131073);assert len(raw)<=131072;return json.loads(raw)
 payload={'message':'ci: record offline Windows parser and selection tests '+commit[:12],'branch':'main','content':base64.b64encode((json.dumps(r,indent=2)+'\n').encode()).decode()}
 try:existing=request('GET');payload['sha']=existing['sha']
 except urllib.error.HTTPError as e:
  if e.code!=404:raise
 request('PUT',payload);print('Published minimal offline Windows parser receipt; no installer qualification.')
if __name__=='__main__':publish()
