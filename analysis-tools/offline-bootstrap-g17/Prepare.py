import hashlib,json,os,shutil,subprocess,sys,urllib.request
from pathlib import Path
ROOT=Path(sys.argv[1]);BASE=Path(__file__).resolve().parents[2];sys.path.insert(0,str(BASE/'scripts'))
if os.environ.get('BNET_OFFLINE_G17')!='lab: approved offline real Setup G17 20261025' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('fresh_hosted_required')
class HTTPSOnly(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  if not newurl.lower().startswith('https://'):raise ValueError('download_redirect_refused')
  return super().redirect_request(req,fp,code,msg,headers,newurl)
report={'matches_pin':False,'signature_accepted':False,'trust_status':None,'ui_helper_ready':False,'error_code':None}
try:
 setup=ROOT/'Battle.net-Setup.exe';opener=urllib.request.build_opener(HTTPSOnly())
 with opener.open('https://downloader.battle.net/download/getInstaller?os=win&installer=Battle.net-Setup.exe',timeout=30) as response:
  if response.status!=200 or not response.url.lower().startswith('https://'):raise ValueError('download_refused')
  data=response.read(4700881)
 setup.write_bytes(data);report['bytes']=len(data);report['sha256']=hashlib.sha256(data).hexdigest();report['matches_pin']=len(data)==4700880 and report['sha256']=='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
 if not report['matches_pin']:raise ValueError('setup_pin_mismatch')
 v=subprocess.run([str(ROOT/'OfflineLauncher.exe'),'verify',str(setup)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=70)
 if v.returncode or len(v.stdout)>4096:raise ValueError('signature_helper_failed')
 sig=json.loads(v.stdout.decode('utf-8-sig'));report['trust_status']=sig['trust_status'];report['signature_accepted']=sig['trust_status']==0 and sig['expected_blizzard_publisher'] is True
 if not report['signature_accepted']:raise ValueError('signature_refused')
 import observe_agent,ui_accessibility as uia
 uia._HELPER=uia.native_helper(observe_agent.clean_environment(os.environ));uia.smoke_check();shutil.copyfile(uia._HELPER[0],ROOT/'NativeUI.exe');report['ui_helper_ready']=True
except Exception as exc:
 s=str(exc);report['error_code']=s if s.replace('_','').isalpha() and len(s)<=80 else 'prepare_operation_failed'
(ROOT/'preflight.json').write_text(json.dumps(report));print(json.dumps(report))
if report['error_code']:raise SystemExit(1)
