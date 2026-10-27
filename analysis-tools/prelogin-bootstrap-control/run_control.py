"""Fresh hosted Windows, ordinary Popen, no Frida import/injection or raw artifacts."""
import json,os,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.append(str(HERE.parent/'prelogin-registry-stack'))
from report import blank,fold,validate,ERROR
PIN='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
def authorized(e,platform):
 return platform=='win32' and all(e.get(k)==v for k,v in dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,BNET_BOOTSTRAP_CONTROL='approved-bootstrap-control-b2').items())
def root_state(handle):
 try:
  v=handle.poll();return 'running' if v is None else ('exited_zero' if v==0 else 'exited_nonzero')
 except OSError:return 'unknown'
def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);validate(r)
 out=Path('output');out.mkdir(exist_ok=True);setup=None;handle=None
 import observe_agent as obs
 original_fetch=obs.fetch_setup;original_snapshot=obs.snapshot;original_popen=subprocess.Popen
 def fetch(destination):
  nonlocal setup
  result=original_fetch(destination);r['bootstrap_pin_match']=result['sha256']==PIN
  if r['bootstrap_pin_match'] is not True:
   r['error_kind']='pin_mismatch';destination.unlink(missing_ok=True);raise obs.LabError('bootstrap_pin_mismatch_refused')
  setup=destination.resolve();return result
 def launch(argv,*args,**kwargs):
  nonlocal handle
  if setup is not None and isinstance(argv,(list,tuple)) and len(argv)==1 and Path(argv[0]).resolve()==setup:
   if handle is not None:raise obs.LabError('duplicate_setup_refused')
   # Original ordinary Popen. Existing observer already requires accepted Authenticode.
   handle=original_popen(argv,*args,**kwargs);r['target_launched']=True;return handle
  return original_popen(argv,*args,**kwargs)
 def snapshot(env):
  raw=original_snapshot(env)
  if handle is not None:
   s=root_state(handle);r['root_state_before_cleanup']=s
   if sum(r['root_samples'].values())>=128:raise RuntimeError('sample_limit')
   r['root_samples'][s]+=1
  return raw
 try:
  if any(x=='frida' or x.startswith('frida.') for x in sys.modules):r['error_kind']='frida_present';raise RuntimeError('frida_present')
  obs.fetch_setup=fetch;obs.snapshot=snapshot;subprocess.Popen=launch
  base=obs.observe(out,150,advance_language=True,advance_install=False,retry_language_when_no_target=True)
  fold(base,r)
 except Exception as exc:
  if r['error_kind'] is None:r['error_kind']=type(exc).__name__ if type(exc).__name__ in ERROR else 'other'
 finally:
  obs.fetch_setup=original_fetch;obs.snapshot=original_snapshot;subprocess.Popen=original_popen
  # No request of this kind is allowed; fail closed if an unexpected import happened.
  if any(x=='frida' or x.startswith('frida.') for x in sys.modules):raise SystemExit('unexpected_frida_import')
  validate(r);(out/'prelogin-bootstrap-control.json').write_text(json.dumps(r,indent=2)+'\n')
  print(json.dumps(dict(target_launched=r['target_launched'],status=r['readiness']['status'],error_kind=r['error_kind'])))
if __name__=='__main__':main()
