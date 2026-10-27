"""Fresh owned Agent: one Retail initialization, never login/finalize/game payload."""
import json,os,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.append(str(ROOT/'agent-interface-lab'));sys.path.append(str(HERE.parent/'prelogin-registry-stack'))
import probe
from retail_protocol import Session,summarize,discover,empty_summary
import form_details
import form_update
from report import blank,validate,ERRORS
PIN='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
def authorized(e,platform):
 return platform=='win32' and all(e.get(k)==v for k,v in dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,RETAIL_PREPARE='approved-retail-prepare-c5').items())
def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);validate(r);out=Path('output');out.mkdir(exist_ok=True)
 import observe_agent as lab
 original_fetch=lab.fetch_setup;original_observe=lab.observe;old_approval=os.environ.get('AGENT_INTERFACE_ONCE')
 def fetch(destination):
  result=original_fetch(destination);r['bootstrap_pin_match']=result['sha256']==PIN
  if r['bootstrap_pin_match'] is not True:destination.unlink(missing_ok=True);raise probe.Stop('bootstrap_not_ready')
  return result
 def observe(*args,**kwargs):
  if kwargs.get('advance_language') is not True or kwargs.get('advance_install') is not False or kwargs.get('seconds')!=120:raise RuntimeError('bootstrap_scope')
  kwargs['retry_language_when_no_target']=True
  return original_observe(*args,**kwargs)
 def identity(state,stage):
  if state not in probe.IDENTITY_STATES or stage not in probe.IDENTITY_STAGES:raise ValueError('identity')
  r['identity_checks']+=1;r['last_identity_state']=state
  if state=='verified_temp_image':r['temp_image_verifications']+=1
  if state not in {'verified','verified_temp_image'} and r['identity_failure_state'] is None:r['identity_failure_state']=state
 def observer(token,port,verify):
  try:
   session=Session(port,token,verify,r)
   data=session.request('GET','/game')
   if not empty_summary(data):r['status']='existing_products_refused';return
   r['initial_summary_empty']=True
   data=session.request('POST','/install')
   r['form_details']=form_details.describe(data.get('form'));r['form']=summarize(data);r['status']='form_observed' if r['form']['form_schema_valid'] else 'form_schema_unknown'
   if r['status']=='form_observed':form_update.execute(session,data,r,lab.is_reparse)
  except Exception as exc:r.update(status='request_failed',error_kind=type(exc).__name__ if type(exc).__name__ in ERRORS else 'other')
 try:
  try:r['metadata']=discover()
  except Exception:r['status']='discovery_failed';return
  os.environ['AGENT_INTERFACE_ONCE']=probe.APPROVAL;lab.fetch_setup=fetch;lab.observe=observe
  r['handshake']=probe.run(out,after_handshake=observer,report_sink=r['handshake'],identity_observer=identity,allow_verified_temp_image=True)
  if r['status']=='not_started':r['status']='handshake_not_ready'
  if r['status'] in {'form_observed','form_schema_unknown'} and (r['handshake']['status']!='handshake_token_observed' or r['identity_failure_state'] is not None):r['status']='identity_changed'
 except Exception as exc:r.update(status='stopped',error_kind=type(exc).__name__ if type(exc).__name__ in ERRORS else 'other')
 finally:
  lab.fetch_setup=original_fetch;lab.observe=original_observe
  if old_approval is None:os.environ.pop('AGENT_INTERFACE_ONCE',None)
  else:os.environ['AGENT_INTERFACE_ONCE']=old_approval
  validate(r);(out/'prelogin-retail-prepare.json').write_text(json.dumps(r,indent=2)+'\n')
  print(json.dumps(dict(status=r['status'],initialization_attempted=r['initialization_attempted'],finalization_requested=False)))
if __name__=='__main__':main()
