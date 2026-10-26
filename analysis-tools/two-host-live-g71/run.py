"""Fresh hosted Windows only. Bounded startup, no login/game install/UI automation."""
import os,sys,json,time,threading,subprocess,socket,ipaddress
from pathlib import Path
from collections import Counter
import frida
from content import Inspector,TARGETS
from Job import Job,creation_time,guarded_process,K
from probe import inspect as probe_ui
from decision import candidate
from inet_content import classify as classify_inet
from response_content import summarize as summarize_response
from inventory import snapshot as snapshot_inventory
import log_diagnosis
import certificate_cache
from semantic_audit import Audit,load_public,local_comparisons
from download_path_audit import load_reference
from transport_audit import TransportAudit
from process_exit_proof import CandidateAlreadyExited
from origin_audit import OriginAudit
from response_origin import ResponseOrigin
base=Path(__file__).resolve().parent;root=Path(os.environ['RUNNER_TEMP'])/'g71-private'
if os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('BNET_G71')!='approved-live-startup-two-hosts-g71':raise SystemExit('hosted_approval_required')
def ps(action):
 r=subprocess.run(['powershell.exe','-NoProfile','-File',str(base/'Gate.ps1'),'-Action',action,'-Root',str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
 if r.returncode:raise RuntimeError('gate_'+action.lower()+'_failed')
root.mkdir(exist_ok=False)
report={'schema':'two-host-live-g71-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'scope':'one_guarded_language_continue_then_bounded_content_observation_no_install_click_no_login_not_full_download','installer_executed':False,'firewall_verified':False,'error':None,'cleanup':False,'fingerprinting_absence_proven':False}
log_before={};log_started=None;startup_diagnostics=[];tls_statuses=[];tls_plaintext_rows=[];tls_out=Inspector();tls_payload_bytes=0;request_audit=None;transport_audit=TransportAudit();origin=None;response_origin=None
language={'status':'not_attempted','continue_attempted':False,'continue_returned':False,'outcome_uncertain':False};action_used=False
inet_rows=[];inet_begun=[];response_rows=[];call_indices={};inet_errors=Counter();inventory_rows=[];late_handles=[];late_processes=[]
inspector=Inspector();counts=Counter();sessions=[];known_pids=set();snapshots=[];lock=threading.RLock();device=None;job=None;armed=False;errors=[];peer_unknown=0
try:
 control=json.loads(Path('output/g71-native-control.json').read_text())
 if control.get('TLS_fixture_trust_removed_before_installer') is not True or control.get('passed') is not True or control.get('source_commit')!=os.environ['GITHUB_SHA'] or control.get('run_id')!=os.environ['GITHUB_RUN_ID']:raise RuntimeError('native_positive_control_required')
 report['native_control_passed']=True
 public_paths,path_reference=load_reference(base);report['download_path_reference']=path_reference;origin=OriginAudit(public_paths)
 # Compile trusted read-only UIA helper before network isolation.
 csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 framework=csc.parent
 refs=[framework/'System.Web.Extensions.dll',framework/'WPF/UIAutomationClient.dll',framework/'WPF/UIAutomationTypes.dll',framework/'WPF/WindowsBase.dll']
 command=[str(csc),'/nologo','/target:exe','/out:'+str(Path(os.environ['RUNNER_TEMP'])/'g71-read-ui.exe'),*['/reference:'+str(x) for x in refs],str(base/'ReadUI.cs')]
 built=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('readonly_UI_compile_failed')
 language_exe=Path(os.environ['RUNNER_TEMP'])/'g71-language-once.exe'
 command=[str(csc),'/nologo','/target:exe','/out:'+str(language_exe),*['/reference:'+str(x) for x in refs],str(base/'LanguageOnce.cs'),str(base.parents[1]/'scripts/language_advance.cs')]
 built=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('language_guard_compile_failed')
 ps('Prepare')
 report['certificate_cache_online']=certificate_cache.run(root,'Online')
 reference=subprocess.run(['powershell.exe','-NoProfile','-File',str(base/'PublicReference.ps1'),'-Root',str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=65)
 if reference.returncode:raise RuntimeError('fixed_public_reference_failed')
 public_tokens,reference_summary=load_public(root);report['fixed_public_reference']=reference_summary
 response_origin=ResponseOrigin(json.loads((root/'public-reference.PRIVATE.json').read_text(encoding='utf-8-sig'))['rows']);origin.on_target=response_origin.target
 request_audit=Audit(public_tokens,local_comparisons(),public_paths)
 config=json.loads((root/'config.json').read_text(encoding='utf-8-sig'));ips={ipaddress.ip_address(x) for x in config['ips']}
 job=Job();device=frida.get_local_device();hook=(base/'hook.js').read_text()
 def attach(pid):
  session=device.attach(pid);sessions.append(session);known_pids.add(pid);session.enable_child_gating();script=session.create_script(hook);ready=threading.Event()
  def message(m,data):
   with lock:
    if m.get('type')!='send':counts['hook_script_error']+=1;return
    p=m['payload'];k=p.get('kind','unknown');counts[k]+=1
    if k=='origin_gap':counts['origin_gap_'+p.get('reason','unknown')]+=1
    if k=='origin_file_closed':origin.close((pid,'file',p['file_handle']))
    if k=='origin_source' and data:
     source=p.get('source')
     if source=='disk_ReadFile_sync':origin.source((pid,'file',p['file_handle']),data,source,p.get('frames',[]))
     elif source in ('recv','WSARecv_immediate'):
      peer=p.get('peer') or {}
      try:selected=ipaddress.ip_address(peer.get('ip','')) in ips and peer.get('port')==80
      except ValueError:selected=False
      if selected:origin.source((pid,p['socket']),data,'selected_two_host_'+source,p.get('frames',[]))
    if k=='socket_closed':
     origin.close((pid,p['socket']))
     transport_audit.close((pid,p['socket']))
     for parser,key in [(inspector,(pid,p['socket'])),(request_audit,('Winsock',pid,p['socket']))]:
      remaining=parser.buffers.pop(key,b'')
      if remaining:
       if parser is inspector:parser.unknown['incomplete_at_close_bytes']+=len(remaining)
       else:parser.unparsed['incomplete_at_close_bytes']+=len(remaining)
    if k=='ready':ready.set()
    if k in ('sspi_handshake_status','sspi_decrypt_status') and len(tls_statuses)<1000:tls_statuses.append(p)
    if k=='sspi_plaintext' and p.get('server') in TARGETS:
     b=bytes(data or b'')
     if len(tls_plaintext_rows)<1000:
      tls_plaintext_rows.append({'server':p['server'],'context_index':p['context_index'],'direction':p['direction'],'status':p['status'],'observed_bytes':len(b),'raw_values_exported':False,'wire_receipt_proven':False})
      if p['direction']=='outgoing_pre_encrypt':
       tls_out.feed((pid,p['context_index']),b)
       if p['server']=='us.version.battle.net':
        if p['status']=='0x00000000':response_origin.feed((pid,p['context_index']),'out',b)
        else:response_origin.reject((pid,p['context_index']),'EncryptMessage_failed')
       request_audit.feed(('SSPI',pid,p['context_index']),b)
      elif p['direction']=='incoming_post_decrypt' and p['server']=='us.version.battle.net':
       request_audit.responses.feed(('SSPI',pid,p['context_index']),b)
       origin.source((pid,'sspi',p['context_index']),b,'version_TLS_plaintext')
       if p['status']=='0x00000000':response_origin.feed((pid,p['context_index']),'in',b)

    if k=='startup_diagnostic' and len(startup_diagnostics)<500:startup_diagnostics.append(p)
    if k=='network_module_category':counts['module_category_'+p.get('category','unknown')]+=1
    if k=='wininet_request_begun':
     if len(inet_begun)<1000:
      row=classify_inet(p,bytes(data or b''))
      if row is not None:
       key=(pid,p.get('call_id'));call_indices.setdefault(key,len(call_indices)+1)
       row.update(observation_index=call_indices[key],api_stage='input_before_call',api_completion_observed=False,api_returned_true=None,error_code=None)
       inet_begun.append(row)
     else:counts['inet_begin_cap']+=1
    if k=='wininet_response_bytes':
     if p.get('server') in TARGETS:origin.source((pid,'inet',counts[k]),bytes(data or b''),'target_InternetReadFile')
     row=summarize_response(p,bytes(data or b''))
     if row is not None and len(response_rows)<1000:response_rows.append(row)
     elif row is None:counts['unattributed_or_other_server_response_bytes']+=len(data or b'')
     else:counts['response_row_cap']+=1
    if k=='wininet_request_input':
     if len(inet_rows)>=1000:counts['inet_report_cap']+=1
     else:
      row=classify_inet(p,bytes(data or b''))
      if row is not None:
       key=(pid,p.get('call_id'));call_indices.setdefault(key,len(call_indices)+1)
       row.update(observation_index=call_indices[key],api_stage='after_return',api_completion_observed=True)
       inet_rows.append(row)
      else:counts['wininet_other_server_inputs']+=1
     if type(p.get('error')) is int:inet_errors[str(p['error'])]+=1
    if k=='bytes' and data:
     peer=p.get('peer')
     accepted=False
     if peer is None: category='peer_query_failed'
     else:
      try:
       address=ipaddress.ip_address(peer['ip']);address=getattr(address,'ipv4_mapped',None) or address
       accepted=address in ips
       category='selected_target_IP' if accepted else 'loopback' if address.is_loopback else 'other_IP'
      except (ValueError,KeyError): category='peer_invalid'
     counts['peer_'+category+'_bytes']+=len(data)
     port=peer.get('port') if peer else None
     counts['port_'+str(port if port in (80,443,1119) else 'other_or_unknown')+'_events']+=1
     if accepted:
      transport_audit.feed((pid,p['socket']),bytes(data))
      inspector.feed((pid,p['socket']),bytes(data))
      request_audit.feed(('Winsock',pid,p['socket']),bytes(data))
      origin.requests((pid,p['socket']),bytes(data),p.get('origin_frames',[]))
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('hook_not_ready')
  return session
 def child(c):
  try:
   attach(c.pid);device.resume(c.pid)
   with lock:counts['children_instrumented']+=1
  except Exception:
   with lock:counts['child_attach_failure']+=1
   try:device.kill(c.pid)
   except Exception:pass
 device.on('child-added',lambda c: threading.Thread(target=child,args=(c,),daemon=True).start())
 # All trust/download/dependency setup occurs before outbound blocking and launch.
 ps('Apply');armed=True;ps('Verify');report['firewall_verified']=True
 report['offline_two_host_resolution_verified']=(root/'offline-resolution-verified').is_file()
 report['certificate_cache_offline']=certificate_cache.run(root,'Offline')
 log_before=log_diagnosis.baseline();log_started=time.time()
 pid=device.spawn([str(root/'Battle.net-Setup.exe')]);job.assign(pid);birth=creation_time(pid);attach(pid)
 device.resume(pid);report['installer_executed']=True
 start=time.monotonic();next_probe=5
 while time.monotonic()-start<120:
  time.sleep(1)
  elapsed=time.monotonic()-start
  if elapsed>=next_probe:
   with lock: scoped=set(known_pids)
   candidates,inv=snapshot_inventory(base,root,scoped)
   inventory_rows.append({'elapsed_seconds':round(elapsed,1),'snapshot':inv})
   for candidate_process in candidates:
    try:handle,late_birth=guarded_process(candidate_process)
    except CandidateAlreadyExited:
     counts['late_candidate_proven_terminated_before_attach']+=1
     continue
    late_handles.append(handle)
    late_processes.append({'pid':candidate_process['pid'],'birth':late_birth,'image_path':candidate_process['image_path']})
    (root/'late-processes.PRIVATE.json').write_text(json.dumps(late_processes))
    job.assign(candidate_process['pid'])
    attach(candidate_process['pid'])
    counts['verified_late_processes_attached']+=1
   with lock:scoped=set(known_pids)
   snapshot=probe_ui(scoped)
   snapshots.append({'elapsed_seconds':round(elapsed,1),'probe':snapshot})
   ps('Verify')
   if not action_used and candidate(snapshot):
    action_used=True
    language={'status':'helper_started','continue_attempted':False,'continue_returned':False,'outcome_uncertain':True}
    try:
     action=subprocess.run([str(language_exe),str(pid),str(birth)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12)
     if len(action.stdout)>4096:raise ValueError('language_output_limit')
     result=json.loads(action.stdout.decode('utf-8-sig'))
     if type(result) is not dict or type(result.get('status')) is not str:raise ValueError('language_output_invalid')
     language=result
     language['elapsed_seconds']=round(time.monotonic()-start,1)
    except subprocess.TimeoutExpired:language['status']='timeout_no_retry'
    except Exception:language['status']='output_failed_no_retry'
    ps('Verify')
   next_probe+=20
  with lock:
   if counts['hook_script_error'] or counts['child_attach_failure'] or inspector.capped:break
 report['observed_seconds']=round(time.monotonic()-start,1)
except Exception as e:
 m=str(e);report['error']=m if m.replace('_','').isalnum() and len(m)<90 else type(e).__name__
finally:
 for mode in ('Online','Offline'):
  cache_report=root/('certificate-cache-'+mode+'.json')
  if cache_report.is_file() and cache_report.stat().st_size<=16384:
   try:report['certificate_cache_'+mode.lower()]=json.loads(cache_report.read_text(encoding='utf-8-sig'))
   except Exception:report['certificate_cache_'+mode.lower()]={'successful':False,'error_type':'invalid_report'}
 if job:
  try:job.close()
  except Exception:report['job_cleanup_failed']=True
 for handle in late_handles:K.CloseHandle(handle)
 if log_started is not None:
  try:report['local_log_diagnosis']=log_diagnosis.collect(log_before,log_started)
  except Exception as e:report['local_log_diagnosis']={'error_type':type(e).__name__,'raw_text_exported':False}
 # Retain blocking until target processes have exited. Restore only on a fresh disposable runner.
 try:ps('Restore');report['cleanup']=True
 except Exception:report['cleanup']=False;report['restore_error']='restore_refused_or_failed'
 with lock:report['content']=inspector.report();report['hook_counts']=dict(counts);report['read_only_UI_snapshots']=snapshots;report['language_action']=language;report['wininet_inputs']=inet_rows;report['wininet_error_codes']=dict(inet_errors);report['wininet_inputs_before_call']=inet_begun;report['wininet_response_chunks']=response_rows;report['process_inventory_snapshots']=inventory_rows
 report['hosts']={h:{'socket_request_rows':sum(r['host']==h for r in inspector.rows),'wininet_input_rows':sum(r['host']==h for r in inet_rows),'wininet_begun_rows':sum(r['host']==h for r in inet_begun),'wininet_response_chunks':sum(r['host']==h for r in response_rows),'verdict':'bounded_API_observation_not_wire_receipt' if any(r['host']==h for r in inspector.rows) or any(r['host']==h for r in inet_rows) or any(r['host']==h for r in inet_begun) or any(r['host']==h for r in response_rows) else 'unknown_no_content_rows'} for h in TARGETS}
 report['startup_diagnostics']=startup_diagnostics
 report['sspi_statuses']=tls_statuses
 report['sspi_plaintext_metadata']=tls_plaintext_rows
 report['sspi_outgoing_HTTP1_classification']=tls_out.report()
 report['sspi_outgoing_HTTP1_classification']['request_grain']='scoped_SSPI_pre_encrypt_API_input_not_wire_or_server_receipt'
 report['request_value_audit']=request_audit.report() if request_audit is not None else {'not_started':True}
 report['accepted_write_transport_audit']=transport_audit.report()
 report['unknown_key_origin_trace']=origin.report() if origin is not None else {'not_started':True}
 report['version_response_key_attribution']=response_origin.report() if response_origin is not None else {'not_started':True}
 report['coverage_complete']=False;report['server_receipt_proven']=False;report['hook_changes_client_timing_possible']=True
 out=Path('output');out.mkdir(exist_ok=True);(out/'two-host-live-g71.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 # Chunked sanitized JSON avoids UI truncation of one long line.
 import base64,hashlib
 payload=json.dumps(report,separators=(',',':')).encode();encoded=base64.b64encode(payload).decode()
 print('G71_MANIFEST='+json.dumps({'run_id':report['run_id'],'source_commit':report['source_commit'],'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'chunks':(len(encoded)+2999)//3000}))
 for index in range(0,len(encoded),3000):print('G71_CHUNK_'+str(index//3000)+'='+encoded[index:index+3000])
if report['error'] or not report['cleanup']:raise SystemExit(1)
