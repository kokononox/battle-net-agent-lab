"""Allowlisted evidence only. Private paths, PIDs, UI strings and environment never leave VM."""
import hashlib,json,os,re,sys
from pathlib import Path
OUT=Path('output');OUT.mkdir(exist_ok=True)
def read(p):
 try:
  if p.stat().st_size>1048576:return {}
  return json.loads(p.read_text(encoding='utf-8-sig'))
 except Exception:return {}
def enum(v):return v if isinstance(v,str) and re.fullmatch('[a-zA-Z0-9_]{1,100}',v) else 'unavailable'
def subset(v,keys):return {k:v[k] for k in keys.split() if k in v and (v[k] is None or isinstance(v[k],(bool,int,float)) or isinstance(v[k],str) and re.fullmatch('[a-zA-Z0-9_]{1,100}',v[k]))}
r={'schema':'offline_bootstrap_g17_v1','source_commit':os.getenv('GITHUB_SHA'),'run_id':os.getenv('GITHUB_RUN_ID'),'status':'not_qualified','installer_launched':None,'installation_verified':False,'full_chain_discovered':False,'all_processes_observed':False,'all_target_egress_blocked_proven':False,'minimum_two_destinations_tested':False,'login_attempted':False,'game_download_requested':False,'install_options_action_requested':False,'components':[]}
pointer=read(OUT/'g17-private-pointer.json');root=Path(pointer['root']) if pointer.get('root') else None
if root:
 pre=read(root/'preflight.json');d=read(root/'driver-result.json');o=read(root/'owner-result.json');u=read(root/'ui-result.json');rec=read(root/'recovery-result.json');launch=read(root/'launch-state.json')
 r['preflight']=subset(pre,'matches_pin signature_accepted trust_status ui_helper_ready error_code bytes');sha=pre.get('sha256','');
 if re.fullmatch('[a-f0-9]{64}',sha):r['preflight']['sha256']=sha
 r['driver']=subset(d,'stage failure_stage error_code gate_verified_before_launch gate_verified_after_observation baseline_canary_connected blocked_canary_connected post_restore_canary_connected target_launch_attempted target_launched owner_exit_confirmed')
 r['owner']=subset(o,'target_launched assigned_before_resume job_active_zero_before_close root_exited new_process_events process_exit_events unresolved_event_count unique_observed_identities observation_seconds')
 r['ui']=subset(u,'language_attempted language_status language_continue_returned outcome_uncertain install_action_requested ui_probe_errors language_probes')
 r['recovery']=subset(rec,'status origin system_identity owned_job_ended registration_changes outside_job_target_candidates restore_refused firewall_restored iis_restored error_code')
 r['installer_launched']=True if launch.get('target_launched') is True else d.get('target_launched')
 # Owner failure message is emitted as a restricted enum, never raw stdout/stderr.
 err=read(root/'owner-stdout.private.txt')
 if err.get('error_code'):r['owner_error_code']=enum(err['error_code'])
 identities=[]
 if isinstance(launch.get('root'),dict):identities.append(launch['root'])
 ep=root/'private-events.jsonl'
 if ep.exists() and ep.stat().st_size<=1048576:
  for line in ep.read_text(encoding='utf-8-sig').splitlines()[:512]:
   try:
    ev=json.loads(line)
    if ev.get('kind')=='new_process' and isinstance(ev.get('identity'),dict):identities.append(ev['identity'])
   except Exception:pass
 seen=set();hashed=0
 names={'battle.net-setup.exe':'Battle.net-Setup.exe','agent.exe':'Agent.exe','battle.net.exe':'Battle.net.exe','battle.net launcher.exe':'Battle.net Launcher.exe','blizzarderror.exe':'BlizzardError.exe','conhost.exe':'conhost.exe','msiexec.exe':'msiexec.exe'}
 def category(p):
  text=str(p).lower();rr=str(root).lower()
  if text==str(root/'Battle.net-Setup.exe').lower():return 'setup_exact'
  if text.startswith(str(root/'stage-temp').lower()+'\\'):return 'staged_temp'
  for env,suffix,label in [('ProgramData','Battle.net','programdata_battle_net'),('ProgramData','Blizzard Entertainment','programdata_blizzard'),('ProgramFiles(x86)','Battle.net','programfiles_battle_net'),('LOCALAPPDATA','Battle.net','localappdata_battle_net'),('SystemRoot','System32','windows_system')]:
   base=str(Path(os.getenv(env,'__not_set__'))/suffix).lower()
   if text.startswith(base+'\\'):return label
  return 'other'
 for identity in identities:
  p=Path(identity.get('image',''));key=(identity.get('pid'),identity.get('created'))
  if key in seen or not identity.get('image'):continue
  seen.add(key);digest=None
  try:
   parents=[p,*list(p.parents)];size=p.stat().st_size
   if not any(x.is_symlink() or bool(getattr(x.lstat(),'st_file_attributes',0)&0x400) for x in parents) and size<=67108864 and hashed+size<=268435456:
    digest=hashlib.sha256(p.read_bytes()).hexdigest();hashed+=size
  except Exception:pass
  item={'name':names.get(p.name.lower(),'other_executable'),'path_category':category(p),'sha256':digest,'signature':'verified_before_gate' if category(p)=='setup_exact' and pre.get('signature_accepted') else 'not_verified','observed_instances':1}
  matching=next((x for x in r['components'] if all(x[k]==item[k] for k in ['name','path_category','sha256'])),None)
  if matching:matching['observed_instances']+=1
  elif len(r['components'])<32:r['components'].append(item)
 good=(pre.get('matches_pin') is True and pre.get('signature_accepted') is True and pre.get('ui_helper_ready') is True and r['installer_launched'] is True and all(d.get(k) is True for k in ['gate_verified_before_launch','gate_verified_after_observation','baseline_canary_connected','post_restore_canary_connected','owner_exit_confirmed']) and d.get('blocked_canary_connected') is False and not d.get('error_code') and all(o.get(k) is True for k in ['assigned_before_resume','job_active_zero_before_close','root_exited']) and rec.get('status')=='restored_after_scoped_exit_checks' and rec.get('system_identity') is True and rec.get('firewall_restored') is True and not rec.get('registration_changes') and not rec.get('outside_job_target_candidates'))
 if good:r['status']='offline_bootstrap_observed_and_restored'
 elif rec.get('restore_refused'):r['status']='quarantined_restore_refused'
 elif pre.get('error_code'):r['status']='preflight_stopped'
(OUT/'offline-g17.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
sys.exit(0 if r['status']=='offline_bootstrap_observed_and_restored' else 1)
