"""Fresh owned Agent: one Retail initialization, never login/finalize/game payload."""
import json,os,re,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.append(str(ROOT/'agent-interface-lab'));sys.path.append(str(HERE.parent/'prelogin-registry-stack'))
import probe
from retail_protocol import Session,summarize,discover,empty_summary
import form_details
import form_update
import transfer_probe
from report import blank,validate,ERRORS
PIN='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
BRANCH='refs/heads/research/prelogin-telemetry-wow-data-provenance'
def authorized(e,platform):
 return platform=='win32' and all(e.get(k)==v for k,v in dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,RETAIL_PREPARE='approved-retail-prepare-c10').items())
def transfer_allowed(e):
 scope=e.get('RETAIL_PREPARE_SCOPE','limited-transfer-c10')
 if scope not in {'limited-transfer-c10','prepare-only-d11'}:raise ValueError('scope_refused')
 return scope=='limited-transfer-c10'
def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('fresh_hosted_once_required')
 if os.environ.get('RETAIL_SUPERVISED')!='job-c10':raise SystemExit('independent_job_required')
 allow_transfer=transfer_allowed(os.environ)
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);validate(r);out=Path('output');out.mkdir(exist_ok=True)
 import observe_agent as lab
 original_fetch=lab.fetch_setup;original_observe=lab.observe;old_approval=os.environ.get('AGENT_INTERFACE_ONCE')
 def fetch(destination):
  result=original_fetch(destination);r['bootstrap_pin_match']=result['sha256']==PIN
  if r['bootstrap_pin_match'] is not True:destination.unlink(missing_ok=True);raise probe.Stop('bootstrap_not_ready')
  return result
 def observe(*args,**kwargs):
  if kwargs.get('advance_language') is not True or kwargs.get('advance_install') is not False or kwargs.get('seconds')!=120:raise RuntimeError('bootstrap_scope')
  # D19: shorten only passive startup observation; all readiness/identity gates remain.
  kwargs['seconds']=30;r['bootstrap_settle']['observation_seconds']=30
  kwargs['retry_language_when_no_target']=True
  result=original_observe(*args,**kwargs);b=r['bootstrap_settle'];b['original_cleanup_attempted']=result.get('cleanup_attempted')
  if b['original_cleanup_attempted']is not True:b['status']='skipped';return result
  try:
   clean=lab.clean_environment(os.environ)
   for attempt in range(4):
    snapshot=lab.snapshot(clean);b['checks']+=1;b['last_process_count']=len(snapshot['processes'])
    if not snapshot['processes']:b['status']='empty';break
    b['status']='remaining'
    if attempt<3:lab.stop_observed(snapshot,clean);b['stop_calls']+=1;time.sleep(1)
  except Exception:b['status']='failed'
  return result
 def identity(state,stage):
  if state not in probe.IDENTITY_STATES or stage not in probe.IDENTITY_STAGES:raise ValueError('identity')
  r['identity_checks']+=1;r['last_identity_state']=state
  if state=='verified_temp_image':r['temp_image_verifications']+=1
  if state not in {'verified','verified_temp_image'} and r['identity_failure_state'] is None:r['identity_failure_state']=state
 def observer(token,port,verify):
  try:
   control=os.environ.get('RETAIL_PREPRODUCT_CONTROL')
   if control=='no-product-t7':
    import preproduct_control
    preproduct_control.execute(port,verify,r['source_commit'],r['run_id'])
    r['status']='preproduct_control_observed';return
   if control not in (None,''):raise ValueError('preproduct_scope')
   session=Session(port,token,verify,r)
   data=session.request('GET','/game')
   if not empty_summary(data):r['status']='existing_products_refused';return
   r['initial_summary_empty']=True
   data=session.request('POST','/install')
   r['form_details']=form_details.describe(data.get('form'));r['form']=summarize(data);r['status']='form_observed' if r['form']['form_schema_valid'] else 'form_schema_unknown'
   if r['status']=='form_observed':
    context=form_update.execute(session,data,r,lab.is_reparse)
    if context is not None and allow_transfer:transfer_probe.execute(session,context[0],context[1],r)
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
  r['limits']['finalization_requested']=r['transfer']['finalization_attempted'];r['limits']['game_payload_download_requested']=r['transfer']['start_attempted']
  r['limits']['full_game_download_requested']=r['transfer']['finalization_attempted']
  transfer_probe.write(r['transfer'])
  validate(r);(out/'prelogin-retail-prepare.json').write_text(json.dumps(r,indent=2)+'\n')
  print(json.dumps(dict(status=r['status'],initialization_attempted=r['initialization_attempted'],finalization_requested=r['transfer']['finalization_attempted'])))
if __name__=='__main__':main()
