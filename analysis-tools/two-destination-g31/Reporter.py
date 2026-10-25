"""Allowlisted evidence only. Private paths, PIDs, UI strings and environment never leave VM."""
import hashlib,json,os,re,sys,base64,zlib
from pathlib import Path
from tls_records import validate_summary
from CriticalEvidence import lines as critical_lines
OUT=Path('output');OUT.mkdir(exist_ok=True)
def read(p):
 try:
  if p.stat().st_size>16777216:return {}
  return json.loads(p.read_text(encoding='utf-8-sig'))
 except Exception:return {}
def enum(v):return v if isinstance(v,str) and re.fullmatch('[a-zA-Z0-9_]{1,100}',v) else 'unavailable'
def subset(v,keys):return {k:v[k] for k in keys.split() if k in v and (v[k] is None or isinstance(v[k],(bool,int,float)) or isinstance(v[k],str) and re.fullmatch('[a-zA-Z0-9_]{1,100}',v[k]))}
r={'schema':'ambient_task_control_g31_v1','source_commit':os.getenv('GITHUB_SHA'),'run_id':os.getenv('GITHUB_RUN_ID'),'scenario':os.getenv('BNET_G31_SCENARIO'),'status':'not_qualified','installer_launched':None,'installation_verified':False,'full_chain_discovered':False,'all_processes_observed':False,'all_target_egress_blocked_proven':False,'minimum_two_destinations_tested':False,'login_attempted':False,'game_download_requested':False,'install_options_action_requested':False,'components':[]}
r['classifier_unit_tests']=read(OUT/'classifier-unit-tests.json');r['recovery_gate_tests']=read(OUT/'g19-gate-tests.json')
pointer=read(OUT/'g31-private-pointer.json');root=Path(pointer['root']) if pointer.get('root') else None
if root:
 pre=read(root/'preflight.json');d=read(root/'driver-result.json');o=read(root/'owner-result.json');u=read(root/'ui-result.json');rec=read(root/'recovery-result.json');launch=read(root/'launch-state.json')
 r['system_baseline']=subset(read(root/'system-baseline-receipt.json'),'system_identity captured');r['system_prelaunch']=subset(read(root/'system-prelaunch-receipt.json'),'system_identity captured registration_changes raw_registration_changes classified_reschedules bits_added bits_modified')
 r['preflight']=subset(pre,'matches_pin signature_accepted trust_status ui_helper_ready error_code bytes');sha=pre.get('sha256','');
 if re.fullmatch('[a-f0-9]{64}',sha):r['preflight']['sha256']=sha
 r['driver']=subset(d,'scenario observation_seconds stage failure_stage error_code gate_verified_before_launch gate_verified_after_observation baseline_canary_connected blocked_canary_connected post_restore_canary_connected target_launch_attempted target_launched owner_exit_confirmed')
 r['owner']=subset(o,'target_launched assigned_before_resume job_active_zero_before_close root_exited new_process_events process_exit_events unresolved_event_count unique_observed_identities observation_seconds')
 r['ui']=subset(u,'language_attempted language_status language_continue_returned outcome_uncertain install_action_requested ui_probe_errors language_probes install_status install_continue_returned install_probes')
 r['ui']['install_probe_seconds']=[x for x in u.get('install_probe_seconds',[])[:12] if type(x)==int and 0<=x<=180]
 from_ui={'language','license','agreement','terms','privacy','error','install','update','permission','administrator','network','login','sign_in','installation','location','folder','shortcut','installing','updating','initializing','connecting','download','failed'}
 fixed_controls={'Window','Pane','Text','Button','ComboBox','Edit','Document','Group','CheckBox','RadioButton','List','ListItem','Hyperlink','ProgressBar','Custom','Other'}
 from_native={'ok','continue','cancel','install','next','back','close','yes','no','agree','english_us','english','language','select_language','battle_net','battle_net_setup','setup','installation_location','change','desktop_shortcut','updating_battle_net','installing_battle_net'}
 r['ui']['ui_samples']=[]
 for sample in u.get('ui_samples',[])[:32]:
  if type(sample)!=dict:continue
  n=sample.get('elapsed_seconds');status=sample.get('status')
  if type(n)!=int or not 0<=n<=180 or status not in {'ok','no_targets','timeout','probe_failed','output_rejected','not_windows'}:continue
  r['ui']['ui_samples'].append({'elapsed_seconds':n,'status':status,'markers':sorted({x for x in sample.get('markers',[]) if x in from_ui}),'controls':sorted({x for x in sample.get('controls',[]) if x in fixed_controls}),'labels':sorted({x for x in sample.get('labels',[]) if x in from_native}),'truncated':sample.get('truncated') is True})
 r['recovery']=subset(rec,'status origin system_identity owned_job_ended proxy_closed proxy_force_terminated proxy_drain_complete registration_changes outside_job_target_candidates restore_refused firewall_restored iis_restored error_code stage bits_new_or_modified bits_snapshot_complete raw_registration_changes classified_reschedules')
 r['recovery_error_shape']=subset(rec.get('error_shape',{}),'type id line source')
 bits0=read(root/'bits-before.json');bits1=read(root/'bits-prelaunch.json');bits2=read(root/'bits-after.json');bw=read(root/'bits-watch.json')
 r['bits']={'scope':'all_users_vm_not_installer_attribution','polling_gap_seconds':None,'requested_poll_interval_seconds':2,'maximum_poll_gap_proven':False,'continuous_event_coverage_proven':False,'baseline_complete':bits0.get('complete',False),'prelaunch_complete':bits1.get('complete',False),'after_complete':bits2.get('complete',False),'baseline_job_count':len(bits0.get('jobs',{})) if bits0.get('complete') else None,'prelaunch_job_count':len(bits1.get('jobs',{})) if bits1.get('complete') else None,'after_job_count':len(bits2.get('jobs',{})) if bits2.get('complete') else None,'watch_complete':bw.get('complete',False),'watch_samples':bw.get('samples',0),'ever_added_max_concurrent':bw.get('ever_added'),'ever_modified_max_concurrent':bw.get('ever_modified'),'distinct_observed_jobs':len({v.get('definition',{}).get('id') for v in bw.get('observed',{}).values()}),'observed_transfer_types':sorted({enum(v.get('definition',{}).get('transfer_type')) for v in bw.get('observed',{}).values()})}
 st=read(root/'svc-trust.json');bind=st.get('binding',{})
 r['svc_trust']=subset(st,'system_identity captured_before_target signature_valid_microsoft');r['svc_trust']['binding']=subset(bind,'capture_complete error_code failure_stage file_sha256')
 r['classifier_live_tests']=read(root/'classifier-live-tests.json');r['classifier_unit_tests']=read(OUT/'classifier-unit-tests.json');r['recovery_gate_tests']=read(OUT/'g19-gate-tests.json')
 r['classification']=read(root/'classification.json')
 r['installer_launched']=True if launch.get('target_launched') is True else d.get('target_launched')
 # Owner failure message is emitted as a restricted enum, never raw stdout/stderr.
 err=read(root/'owner-stdout.private.txt')
 if err.get('error_code'):r['owner_error_code']=enum(err['error_code']);r['owner_failure_diagnostic']=subset(err,'failure_stage error_type error_hresult');r['owner_failure_proof']=subset(read(root/'owner-failure.json'),'target_launched assigned_before_resume root_created job_active_zero_before_close root_exited failure_stage')
 identities=[]
 if isinstance(launch.get('root'),dict):identities.append(dict(launch['root'],evidence='job_observed'))
 ep=root/'private-events.jsonl'
 if ep.exists() and ep.stat().st_size<=1048576:
  for line in ep.read_text(encoding='utf-8-sig').splitlines()[:512]:
   try:
    ev=json.loads(line)
    if ev.get('kind')=='new_process' and isinstance(ev.get('identity'),dict):identities.append(dict(ev['identity'],evidence='job_observed'))
   except Exception:pass
 for item in read(root/'outside-candidates.json').get('items',[])[:32]:identities.append(dict(item,evidence='post_job_unattributed'))
 # Count changed registrations by kind; names, commands and task XML remain private.
 before=read(root/'registrations-before.json');after=read(root/'registrations-after.json');r['registration_changes_by_kind']={};r['registration_differences']=[]
 r['registration_diff_complete']=all(k in before and k in after for k in ['services','tasks'])
 for kind in ['services','tasks']:
  a=before.get(kind,{}) if r['registration_diff_complete'] else {};b=after.get(kind,{}) if r['registration_diff_complete'] else {}
  r['registration_changes_by_kind'][kind]=sum(a.get(k)!=b.get(k) for k in set(a)|set(b)) if a and b else None
  for key in sorted(set(a)|set(b)):
   if a.get(key)==b.get(key):continue
   label=key.split('\\')[-1]
   if not re.fullmatch('[A-Za-z][A-Za-z0-9_. ()-]{0,89}',label):label='redacted_identifier'
   def image_names(snapshot):
    value=snapshot.get('service_commands' if kind=='services' else 'task_images',{}).get(key,[])
    if isinstance(value,str):value=[value]
    result=[]
    for text in value[:8]:
     matches=re.findall(r'(?i)([a-z0-9_.-]+[.]exe)',text)
     result.extend(matches[:3])
    return sorted(set(result))
   r['registration_differences'].append({'kind':kind,'identifier':label,'identity_sha256':hashlib.sha256(key.encode()).hexdigest(),'change':'added' if key not in a else 'removed' if key not in b else 'modified','image_names_before':image_names(before),'image_names_after':image_names(after),'command_or_action_images_changed':before.get('service_commands' if kind=='services' else 'task_images',{}).get(key)!=after.get('service_commands' if kind=='services' else 'task_images',{}).get(key)})
   if kind=='services':
    x=before.get('service_config',{}).get(key,{});y=after.get('service_config',{}).get(key,{})
    r['registration_differences'][-1]['changed_config_fields']=[k for k in ['PathName','StartMode','StartName'] if x.get(k)!=y.get(k)]
    if key=='BITS':r['registration_differences'][-1]['start_mode_before']=enum(x.get('StartMode'));r['registration_differences'][-1]['start_mode_after']=enum(y.get('StartMode'))
   if kind=='tasks':
    def shape(xml):
     import xml.etree.ElementTree as E
     result={}
     def walk(node,path):
      result[path]=(tuple(sorted(node.attrib.items())),(node.text or '').strip());counts={}
      for child in node:
       label=child.tag.split('}')[-1];counts[label]=counts.get(label,0)+1;walk(child,path+'/'+label+'['+str(counts[label])+']')
     try:walk(E.fromstring(xml),'Task')
     except Exception:return None
     return result
    x=shape(before.get('task_xml',{}).get(key,''));y=shape(after.get('task_xml',{}).get(key,''))
    if x is not None and y is not None:
     r['registration_differences'][-1]['changed_xml_fields']=[k for k in sorted(set(x)|set(y)) if x.get(k)!=y.get(k)][:32]
     r['registration_differences'][-1]['raw_xml_only_difference']=x==y


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
  item={'name':names.get(p.name.lower(),'other_executable'),'path_category':category(p),'sha256':digest,'signature':'verified_before_gate' if category(p)=='setup_exact' and pre.get('signature_accepted') else 'not_verified','observed_instances':1,'evidence':identity.get('evidence','unavailable')}
  matching=next((x for x in r['components'] if all(x[k]==item[k] for k in ['name','path_category','sha256','evidence'])),None)
  if matching:matching['observed_instances']+=1
  elif len(r['components'])<32:r['components'].append(item)
 r['online_preflight']=read(root/'online-preflight.json')
 r['proxy_drain']=subset(read(root/'proxy-drain.json'),'complete active_handlers')
 r['task_mutation_audit']=read(root/'task-mutation-audit.json')
 r['focus_tasks']=read(root/'focus-task-summary.json')
 r['no_setup_control']=subset(read(root/'no-setup-control.json'),'scenario installer_execution_disabled_in_native_helper native_run_refusal_verified installer_execute_requested setup_download_and_signature_preparation_matched observation_seconds')
 r['process_diagnostics']=read(root/'process-diagnostics.json')
 r['completion_evidence']=read(root/'completion-evidence.json')
 r['application_events']=read(root/'application-events.json')
 r['certificate_preparation']=read(root/'certificate-preparation.json')
 r['installer_error_codes']=read(root/'installer-error-codes.json')
 r['windows_tls_events']=read(root/'windows-tls-events.json')
 r['request_metadata']=[];r['proxy_event_counts']={};r['files_evidence']=read(root/'files-evidence.json')
 proxylog=root/'proxy-private.jsonl'
 if proxylog.exists() and proxylog.stat().st_size<=1048576:
  for line in proxylog.read_text(encoding='utf-8-sig').splitlines()[:8192]:
   try:
    ev=json.loads(line);kind=enum(ev.get('kind'));host=ev.get('host') if ev.get('host') in {'level3.blizzard.com','us.version.battle.net'} else 'other'
    key=kind+':'+host+':'+enum(ev.get('reason',''));r['proxy_event_counts'][key]=r['proxy_event_counts'].get(key,0)+1
    if kind in {'http_request','http_response','tls_transfer','tls_transfer_final'} and len(r['request_metadata'])<256:
     clean={k:v for k,v in ev.items() if k in {'kind','host','method','port','path_sha256','query_present','request_body_bytes','request_body_sha256','response_bytes','status','client_to_server_bytes','server_to_client_bytes','tls_hello_read_bytes','tls_hello_attempted_bytes','tls_hello_sent_bytes','client_read_bytes','client_attempted_bytes','client_sent_bytes','server_read_bytes','server_attempted_bytes','server_sent_bytes','end_reason','send_error_partial_possible'}};
     if kind=='tls_transfer_final' and 'tls_records' in ev:
      try:clean['tls_records']=validate_summary(ev['tls_records'])
      except (ValueError,TypeError,KeyError):pass
     r['request_metadata'].append(clean)
   except Exception:pass
 r['install_options_action_requested']=u.get('install_action_requested') is True
 r['https_payload_classified']=False;r['external_brokers_auto_enrolled']=False;r['tls_scope']='sni_and_pinned_ip_not_decrypted_http_authority';r['ambient_drift_did_not_waive_recovery']=True
 good=(r['system_baseline'].get('system_identity') is True and r['system_prelaunch'].get('system_identity') is True and r['system_prelaunch'].get('registration_changes')==0 and pre.get('matches_pin') is True and pre.get('signature_accepted') is True and pre.get('ui_helper_ready') is True and r['installer_launched'] is True and all(d.get(k) is True for k in ['gate_verified_before_launch','gate_verified_after_observation','baseline_canary_connected','post_restore_canary_connected','owner_exit_confirmed']) and d.get('blocked_canary_connected') is False and not d.get('error_code') and all(o.get(k) is True for k in ['assigned_before_resume','job_active_zero_before_close','root_exited']) and rec.get('status')=='restored_after_scoped_exit_checks' and rec.get('system_identity') is True and rec.get('firewall_restored') is True and not rec.get('registration_changes') and not rec.get('outside_job_target_candidates'))
 good=good and r['bits']['watch_complete'] is True and rec.get('bits_snapshot_complete') is True and not rec.get('bits_new_or_modified')
 control_good=(pre.get('matches_pin') is True and pre.get('signature_accepted') is True and r['system_baseline'].get('system_identity') is True and r['system_prelaunch'].get('system_identity') is True and r['system_prelaunch'].get('registration_changes')==0 and rec.get('bits_snapshot_complete') is True and not rec.get('bits_new_or_modified') and not rec.get('registration_changes') and not rec.get('outside_job_target_candidates') and r['scenario']=='no_setup' and r['installer_launched'] is False and d.get('target_launch_attempted') is False and d.get('observation_seconds')==90 and all(d.get(k) is True for k in ['gate_verified_before_launch','gate_verified_after_observation','baseline_canary_connected','post_restore_canary_connected']) and d.get('blocked_canary_connected') is False and rec.get('status')=='restored_after_scoped_exit_checks' and rec.get('system_identity') is True and r['bits']['watch_complete'] is True and not d.get('error_code'))
 required_tests=(r['classifier_live_tests'].get('all_passed') is True and r['classifier_unit_tests'].get('all_passed') is True and r['recovery_gate_tests'].get('all_passed') is True and r['svc_trust'].get('signature_valid_microsoft') is True)
 good=good and required_tests;control_good=control_good and required_tests
 if control_good:r['status']='offline_no_setup_control_observed_and_restored'
 elif good:r['status']='offline_bootstrap_observed_and_restored'
 elif rec.get('restore_refused'):r['status']='quarantined_restore_refused'
 elif pre.get('error_code'):r['status']='preflight_stopped'
if root and r.get('installer_launched') is True and r.get('driver',{}).get('gate_verified_before_launch') is True and r.get('driver',{}).get('gate_verified_after_observation') is True:
 r['status']='two_host_bootstrap_observed_restore_refused' if r.get('recovery',{}).get('restore_refused') else 'two_host_bootstrap_observed_cleanup_unverified'
 if r.get('recovery',{}).get('status')=='restored_after_scoped_exit_checks':r['status']='two_host_bootstrap_observed_and_restored'
 r['minimum_two_destinations_tested']=True # Bounded restricted experiment, never proof of sufficiency/minimality.
if root and r.get('scenario')=='ambient_no_setup':
 r['installer_launched']=False
 r['minimum_two_destinations_tested']=False
 observed=(r.get('preflight',{}).get('matches_pin') is True and r.get('preflight',{}).get('signature_accepted') is True and r.get('certificate_preparation',{}).get('status')=='online_chain_validated_before_isolation' and r.get('no_setup_control',{}).get('native_run_refusal_verified') is True and r.get('no_setup_control',{}).get('installer_execute_requested') is False and r.get('system_baseline',{}).get('system_identity') is True and r.get('system_prelaunch',{}).get('system_identity') is True and r.get('driver',{}).get('blocked_canary_connected') is False and r.get('driver',{}).get('baseline_canary_connected') is True and r.get('no_setup_control',{}).get('installer_execution_disabled_in_native_helper') is True and r.get('driver',{}).get('target_launch_attempted') is False and r.get('driver',{}).get('target_launched') is False and r.get('driver',{}).get('observation_seconds')==270 and r.get('driver',{}).get('gate_verified_before_launch') is True and r.get('driver',{}).get('gate_verified_after_observation') is True and r.get('bits',{}).get('watch_complete') is True)
 r['status']='ambient_control_incomplete'
 if observed:
  r['status']='ambient_control_observed_cleanup_unverified'
  if r.get('recovery',{}).get('restore_refused') is True:r['status']='ambient_control_observed_restore_refused'
  elif r.get('recovery',{}).get('status')=='restored_after_scoped_exit_checks' and r.get('driver',{}).get('post_restore_canary_connected') is True:r['status']='ambient_control_observed_and_restored'
critical_record,critical_receipt_lines=critical_lines(r)
(OUT/'core-g31.json').write_text(json.dumps(critical_record,indent=2))
(OUT/'online-g31.json').write_text(json.dumps(r,indent=2))
raw=json.dumps(r,sort_keys=True,separators=(',',':')).encode();packed=base64.b64encode(zlib.compress(raw)).decode();parts=[packed[i:i+600] for i in range(0,len(packed),600)]
for line in critical_receipt_lines:print(line,flush=True)
print('G31_STATE '+json.dumps({'scenario':r['scenario'],'status':r['status'],'installer_launched':r['installer_launched'],'registration_changes':r.get('recovery',{}).get('registration_changes'),'bits_watch_complete':r.get('bits',{}).get('watch_complete')}))
print('G31_REPORT_MANIFEST '+json.dumps({'parts':len(parts),'raw_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
for i,part in enumerate(parts,1):print('G31_REPORT_PART '+str(i)+'/'+str(len(parts))+' '+part)

for line in critical_receipt_lines:print(line,flush=True)

sys.exit(0 if r['status']=='ambient_control_observed_and_restored' else 1)
