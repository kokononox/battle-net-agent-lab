"""Ordinary Popen plus registry-only attach to verified bootstrap only, after native gates."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.append(str(HERE.parent/'prelogin-registry-stack'));sys.path.append(str(HERE.parent/'prelogin-wire-h2'))
from attach_session import Session,ERRORS,kind
from report import blank,fold,validate,native_passed
PIN='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
def authorized(e,platform):
 return platform=='win32' and all(e.get(k)==v for k,v in dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,BNET_REGISTRY_ONLY='approved-registry-only-b4').items())
def root_state(handle):
 try:
  v=handle.poll();return 'running' if v is None else ('exited_zero' if v==0 else 'exited_nonzero')
 except OSError:return 'unknown'
def baseline():
 import winreg
 from registry_events import UUID
 r=dict(status='error',value_present=False,valid_uuid=False)
 try:
  with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Blizzard Entertainment\Blizzard Error',0,winreg.KEY_READ) as k:v,t=winreg.QueryValueEx(k,'UserUUID')
  r.update(status='present',value_present=True,valid_uuid=bool(t==winreg.REG_SZ and type(v) is str and UUID.fullmatch(v.encode('ascii',errors='replace'))))
 except FileNotFoundError:r['status']='absent'
 except OSError:pass
 return r
def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);validate(r)
 out=Path('output');out.mkdir(exist_ok=True);setup=None;handle=None;attached=None
 import observe_agent as obs
 original_fetch=obs.fetch_setup;original_snapshot=obs.snapshot;original_popen=subprocess.Popen
 def fetch(destination):
  nonlocal setup
  result=original_fetch(destination);r['bootstrap_pin_match']=result['sha256']==PIN
  if r['bootstrap_pin_match'] is not True:
   destination.unlink(missing_ok=True);raise obs.LabError('bootstrap_pin_mismatch_refused')
  setup=destination.resolve();return result
 def launch(argv,*args,**kwargs):
  nonlocal handle,attached
  if setup is not None and isinstance(argv,(list,tuple)) and len(argv)==1 and Path(argv[0]).resolve()==setup:
   if handle is not None:raise obs.LabError('duplicate_setup_refused')
   handle=original_popen(argv,*args,**kwargs);r['target_launched']=True
   # Holding the Popen handle preserves ownership of this process object.
   original_identity=None
   def verify():
    nonlocal original_identity
    i=identity(handle.pid);now=(i['creation'],str(Path(i['path']).resolve()).lower())
    if handle.poll() is not None or Path(i['path']).resolve()!=setup or obs.is_reparse(setup) or hashlib.sha256(setup.read_bytes()).hexdigest()!=PIN:raise RuntimeError('target_identity')
    if not obs.signature(setup,obs.clean_environment(os.environ))['accepted_for_execution']:raise RuntimeError('signature')
    if original_identity is not None and now!=original_identity:raise RuntimeError('identity_changed')
    original_identity=now
   attached=Session(frida,device,setup,PIN);r['target_attach']=attached.start(handle.pid,verify,32)
   return handle
  return original_popen(argv,*args,**kwargs)
 def snapshot(env):
  raw=original_snapshot(env)
  if handle is not None:
   s=root_state(handle);r['root_state_before_cleanup']=s
   if sum(r['root_samples'].values())>=128:raise RuntimeError('sample_limit')
   r['root_samples'][s]+=1
  return raw
 try:
  import frida
  from native_identity import identity
  from native_gate import fixture
  from attach_session import bounded
  if frida.__version__!='17.24.2':raise RuntimeError('frida_version')
  device=bounded(frida,frida.get_local_device)
  env=obs.clean_environment(os.environ)
  r['native_gate']=[fixture(frida,device,arch,env) for arch in ('x64','x86')]
  if not native_passed(r['native_gate']):r['status']='native_gate_failed_no_target';return
  r['baseline_before_target']=baseline()
  if r['baseline_before_target']['status']=='error':raise RuntimeError('baseline_error')
  obs.fetch_setup=fetch;obs.snapshot=snapshot;subprocess.Popen=launch
  base=obs.observe(out,150,advance_language=True,advance_install=False,retry_language_when_no_target=True)
  fold(base,r);r['status']='observation_complete' if base['status']!='stopped' else 'stopped'
 except Exception as exc:r.update(status='stopped',error_kind=kind(exc))
 finally:
  obs.fetch_setup=original_fetch;obs.snapshot=original_snapshot;subprocess.Popen=original_popen
  if attached:
   attached.close();r['registry']=attached.summary()
  # Covers a launch-wrapper failure before observe() receives the Popen object.
  if handle is not None and handle.poll() is None:
   handle.kill();handle.wait(timeout=5)
  if r['target_launched']:r['baseline_after_target']=baseline()
  validate(r);(out/'prelogin-registry-only.json').write_text(json.dumps(r,indent=2)+'\n')
  print(json.dumps(dict(target_launched=r['target_launched'],status=r['status'],minimal_attach=r['target_attach']['status'])))
if __name__=='__main__':main()
