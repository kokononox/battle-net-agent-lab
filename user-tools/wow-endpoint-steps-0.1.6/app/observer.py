import base64,ipaddress,json,os,subprocess,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
ALLOWED_STATES={'Bound','Closed','CloseWait','Closing','DeleteTCB','Established','FinWait1','FinWait2','LastAck','Listen','SynReceived','SynSent','TimeWait'}
def clean(result):
 if not isinstance(result,dict):return {'status':'monitor_inconclusive'}
 out={k:result[k] for k in ('status','elapsed_seconds','tcp_query_errors','process_query_errors','owned_process_instances_seen','wfp_query_status','wfp_events_read','wfp_query_at_limit','matching_wfp_block_events','target_established_in_new_process_seen') if k in result}
 out['scope']='any_group_target' if result.get('group_monitor') is True else 'single_target'
 out.update(audit_settings_changed=False,rule_causality_proven=False,payload_read=False)
 out['target_tcp_states']=[s for s in result.get('target_tcp_states',[]) if s in ALLOWED_STATES]
 out['public_tcp_endpoints']=[]
 for r in result.get('tcp_endpoints',[])[:500]:
  try:
   if ipaddress.ip_address(r['ip']).is_global and type(r['port']) is int and 1<=r['port']<=65535 and r['state'] in ALLOWED_STATES:
    out['public_tcp_endpoints'].append({k:r[k] for k in ('ip','port','state','samples','new_process_seen')})
  except (KeyError,ValueError,TypeError):continue
 if out.get('target_established_in_new_process_seen') is True:out['finding']='target_established_in_new_process_observed'
 elif type(out.get('matching_wfp_block_events')) is int and out['matching_wfp_block_events']>0:out['finding']='matching_windows_block_decision_observed'
 elif out['target_tcp_states']:out['finding']='target_socket_observed_freshness_unproven'
 else:out['finding']='no_target_evidence_in_sample'
 out['interpretation']='WFP matches indicate a Windows block decision for the selected process lifetime and target; they do not identify the responsible rule. TCP samples can include preexisting sockets. No event or socket is not proof of blocking or no traffic. Other destinations observed are not proven fallback.'
 return out

def start(path):
 path=Path(path);stem=path.with_suffix('')
 env=os.environ.copy();env['WOW_STEPS_MONITOR_JOURNAL']=str(path)
 script=str(BASE/'app/monitor.ps1').replace("'","''")
 code="& ([scriptblock]::Create([IO.File]::ReadAllText('"+script+"')))"
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 proc=subprocess.Popen([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 end=time.monotonic()+12
 while time.monotonic()<end:
  if stem.with_suffix('.monitor-ready').exists() and proc.poll() is None:return
  if proc.poll() is not None:break
  time.sleep(.1)
 raise RuntimeError('monitor_not_ready_restore_required')

def signal_stop(path):
 marker=Path(path).with_suffix('.monitor-stop')
 if not marker.exists():marker.write_text(json.dumps({'epoch_ms':int(time.time()*1000)}))

def stop(path):
 path=Path(path);stem=path.with_suffix('')
 signal_stop(path)
 result=stem.with_suffix('.monitor-result');end=time.monotonic()+25
 while time.monotonic()<end:
  if result.exists():
   try:return clean(json.loads(result.read_text('utf-8-sig')))
   except (OSError,ValueError,TypeError):return {'status':'monitor_inconclusive'}
  # No monitor was started (e.g. rule creation failed); do not delay cleanup.
  if not stem.with_suffix('.monitor-ready').exists():return {'status':'monitor_not_started'}
  time.sleep(.2)
 return {'status':'monitor_result_pending_or_unavailable','audit_settings_changed':False,'rule_causality_proven':False}
