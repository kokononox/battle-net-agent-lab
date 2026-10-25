"""Small independently verifiable receipt; never a replacement for the full report."""
import base64,hashlib,json,re,zlib
SCHEMA='two_host_critical_receipt_v1';MAX_BYTES=16384;MAX_PARTS=16
FIELDS={'schema','source_commit','run_id','scenario','status','installation_verified','full_report_bytes','full_report_sha256','driver','recovery','assessment','main_client_records','main_records_omitted','registration_differences','registration_differences_omitted','no_setup_control','focus_task_outcomes'}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def enum(v):return v if type(v)==str and re.fullmatch('[A-Za-z0-9_]{1,100}',v) else 'unavailable'
def subset(d,keys):
 return {k:d[k] for k in keys.split() if k in d and (d[k] is None or type(d[k]) in (bool,int) or type(d[k])==str and re.fullmatch('[A-Za-z0-9_]{1,100}',d[k]))}
def build(report):
 full=canonical(report)
 core={k:report.get(k) for k in ['source_commit','run_id','scenario','status']};core.update(schema=SCHEMA,installation_verified=False,full_report_bytes=len(full),full_report_sha256=hashlib.sha256(full).hexdigest())
 core['no_setup_control']=subset(report.get('no_setup_control',{}),'installer_execution_disabled_in_native_helper native_run_refusal_verified installer_execute_requested observation_seconds')
 core['focus_task_outcomes']=[subset(x,'identifier observed_change_count changed_without_setup automatic_exemption_granted') for x in report.get('focus_tasks',{}).get('tasks',[])[:4]]
 core['driver']=subset(report.get('driver',{}),'error_code failure_stage gate_verified_before_launch gate_verified_after_observation baseline_canary_connected blocked_canary_connected post_restore_canary_connected owner_exit_confirmed observation_seconds')
 core['recovery']=subset(report.get('recovery',{}),'status stage error_code owned_job_ended proxy_closed proxy_drain_complete restore_refused firewall_restored iis_restored registration_changes raw_registration_changes classified_reschedules outside_job_target_candidates bits_new_or_modified bits_snapshot_complete system_identity')
 core['assessment']=subset(report.get('completion_evidence',{}).get('assessment',{}),'package_installation_verified complete_installation_verified setup_natural_zero_exit_observed signed_client_and_launcher_verified uninstall_registration_matches main_process_survival_60s_observed client_login_window_marker_over_30s client_login_controls_observed_over_30s client_no_type_switch_instances client_typed_subprocess_instances')
 mains=[x for x in report.get('process_diagnostics',{}).get('records',[]) if x.get('kind')=='client' and x.get('role')=='no_type_switch'];core['main_client_records']=[subset(x,'observed_start_ms observed_lifetime_ms alive_before_controller_termination exit_event_ms terminated_by_controller_if_alive') for x in mains[:4]];core['main_records_omitted']=max(0,len(mains)-4)
 changes=report.get('registration_differences',[]);core['registration_differences']=[];core['registration_differences_omitted']=max(0,len(changes)-8)
 for d in changes[:8]:
  clean={k:enum(d.get(k)) for k in ['kind','change']};name=d.get('identifier','');digest=d.get('identity_sha256','')
  clean['identifier']=name if re.fullmatch(r'[A-Za-z][A-Za-z0-9_. ()-]{0,89}',name) else 'redacted_identifier';clean['identity_sha256']=digest if re.fullmatch('[a-f0-9]{64}',digest) else 'unavailable';clean['changed_xml_fields']=[s for s in d.get('changed_xml_fields',[])[:8] if type(s)==str and re.fullmatch(r'[A-Za-z0-9_/\[\]]{1,180}',s)];clean['command_or_action_images_changed']=d.get('command_or_action_images_changed') is True;core['registration_differences'].append(clean)
 validate(core,report.get('source_commit'),report.get('run_id'));return core

def validate(d,sha,run):
 if type(d)!=dict or set(d)!=FIELDS or d.get('schema')!=SCHEMA or d.get('source_commit')!=sha or d.get('run_id')!=run or not re.fullmatch('[a-f0-9]{40}',str(sha)) or not re.fullmatch('[0-9]{1,24}',str(run)):raise ValueError('critical_identity_or_fields')
 if d.get('installation_verified') is not False or not re.fullmatch('[a-f0-9]{64}',d.get('full_report_sha256','')) or type(d.get('full_report_bytes'))!=int or not 0<d['full_report_bytes']<=262144:raise ValueError('critical_claim_or_full_manifest')
 def walk(v,depth=0):
  if depth>8:raise ValueError('critical_depth')
  if v is None or type(v) in (bool,int):return
  if type(v)==str:
   if len(v)>180 or not re.fullmatch(r'[A-Za-z0-9_.:/\[\] ,+()=-]*',v):raise ValueError('critical_string')
  elif type(v)==list:
   if len(v)>16:raise ValueError('critical_array')
   for x in v:walk(x,depth+1)
  elif type(v)==dict:
   if len(v)>32:raise ValueError('critical_object')
   for k,x in v.items():walk(k,depth+1);walk(x,depth+1)
  else:raise ValueError('critical_value')
 walk(d)
 if len(canonical(d))>MAX_BYTES:raise ValueError('critical_size')
 return d

def lines(report):
 core=build(report);raw=canonical(core);packed=base64.b64encode(zlib.compress(raw)).decode();parts=[packed[n:n+600] for n in range(0,len(packed),600)]
 if not 1<=len(parts)<=MAX_PARTS:raise ValueError('critical_part_bound')
 result=['G31_CORE_MANIFEST '+json.dumps({'parts':len(parts),'raw_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})]
 result += ['G31_CORE_PART '+str(i)+'/'+str(len(parts))+' '+s for i,s in enumerate(parts,1)]
 return core,result

def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('critical_duplicate_key')
  out[k]=v
 return out

def extract(text,sha,run):
 ms=list(re.finditer(r'G31_CORE_MANIFEST (\{[^\r\n]+\})',text));found=[]
 for i,m in enumerate(ms):
  try:
   meta=json.loads(m.group(1),object_pairs_hook=unique)
   if set(meta)!={'parts','raw_bytes','sha256'} or type(meta['parts'])!=int or not 1<=meta['parts']<=MAX_PARTS or type(meta['raw_bytes'])!=int or not 0<meta['raw_bytes']<=MAX_BYTES or not re.fullmatch('[a-f0-9]{64}',meta['sha256']):continue
   block=text[m.end():ms[i+1].start() if i+1<len(ms) else len(text)];rows=re.findall(r'G31_CORE_PART (\d+)/(\d+) ([A-Za-z0-9+/=]+)',block)
   if len(rows)!=meta['parts'] or [int(x[0]) for x in rows]!=list(range(1,meta['parts']+1)) or any(int(x[1])!=meta['parts'] or len(x[2])>600 for x in rows):continue
   packed=base64.b64decode(''.join(x[2] for x in rows),validate=True);dec=zlib.decompressobj();raw=dec.decompress(packed,MAX_BYTES+1)
   if len(raw)!=meta['raw_bytes'] or not dec.eof or dec.unused_data or dec.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=meta['sha256']:continue
   value=validate(json.loads(raw,object_pairs_hook=unique),sha,run);found.append((raw,value,meta))
  except (ValueError,KeyError,TypeError,zlib.error):continue
 if not found:raise ValueError('no_verified_critical_receipt')
 return found[-1]
