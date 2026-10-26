"""Controlled x86/x64 P/Invoke Winsock fixture; never attach to Battle.net.
Only sanitized verdicts/byte counts leave this controller. Raw candidates remain
volatile and temporary fixture files contain only public/synthetic test values.
"""
import os,json,time,hashlib,threading,tempfile,subprocess,ctypes as C
from ctypes import wintypes as W
from pathlib import Path
from collections import Counter
import frida
from Job import Job,guarded_process,K
from pre_send_gate import load_policy,CDN_HOST,VERSION_HOST
from download_path_audit import load_reference,full_object_size
from native_admission import admit_exact
from pre_send_fixture import Sink
BASE=Path(__file__).resolve().parent
K.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];K.GetExitCodeProcess.restype=W.BOOL

def vectors(base):
 refs,_=load_reference(base)
 path=next(p for p in sorted(refs) if full_object_size(p,refs) is not None and not refs.ranges.get(p) and full_object_size(p,refs)>1)
 size=full_object_size(path,refs)
 def req(p=path,h=CDN_HOST,headers=b'',body=b''):
  return ('GET '+p+' HTTP/1.1\r\nHost: '+h+'\r\nAccept: */*\r\nConnection: close\r\n').encode()+headers+b'\r\n'+body
 full=req(headers=('Range: bytes=0-'+str(size-1)+'\r\n').encode())
 raw=req();meta=req('/v2/products/agent/versions',VERSION_HOST)
 # label, bytes, native mode, expected original call count, expected receipt
 cases=[('public_CDN',raw,'single',1,raw),('public_CDN_full_range',full,'single',1,full),('public_metadata',meta,'single',1,meta),
 ('query_identifier',req(path+'?id=PRIVATE_SENTINEL'),'single',0,b''),
 ('user_agent_identifier',req(headers=b'User-Agent: PRIVATE_SENTINEL\r\n'),'single',0,b''),
 ('cookie_identifier',req(headers=b'Cookie: PRIVATE_SENTINEL\r\n'),'single',0,b''),
 ('authorization_identifier',req(headers=b'Authorization: PRIVATE_SENTINEL\r\n'),'single',0,b''),
 ('body_identifier',req(body=b'PRIVATE_SENTINEL'),'single',0,b''),
 ('unknown_header',req(headers=b'X-Device: PRIVATE_SENTINEL\r\n'),'single',0,b''),
 ('range_one_byte_short',req(headers=('Range: bytes=0-'+str(size-2)+'\r\n').encode()),'single',0,b''),
 ('unknown_host',req(h='PRIVATE_SENTINEL.invalid'),'single',0,b''),
 ('pipelined_request_tail',raw+raw,'single',0,b''),
 ('incomplete_headers',raw[:-1],'single',0,b''),
 ('opaque_TLS',b'\x16\x03\x03\x00\x10PRIVATE_SENTINEL','single',0,b''),
 ('duplicate_host',req(headers=('Host: '+CDN_HOST+'\r\n').encode()),'single',0,b''),
 ('transfer_encoding',req(headers=b'Transfer-Encoding: chunked\r\n'),'single',0,b''),
 ('noncanonical_benign',raw.replace(b'Connection: close',b'Connection: keep-alive'),'single',0,b''),
 ('two_actual_fragment_calls',raw,'split',0,b''),
 ('WSASend_bypass_attempt',raw,'wsa',0,b''),
 ('wrong_peer_binding',raw,'wrong_peer',0,b''),
 ('malformed_policy_reply',raw,'bad_reply',0,b''),
 ('unapproved_send_flags',raw,'flags',0,b''),
 ('approved_then_private_tail',raw,'tail',1,raw),
 ('buffer_mutation_after_snapshot',raw,'mutate',1,raw)]
 return cases

def run_case(exe,arch,policy,case,tmp):
 label,raw,mode,expected_calls,want=case
 inp=tmp/(arch+'-'+label+'.bin');inp.write_bytes(raw)
 marker=tmp/(arch+'-'+label+'.signal')
 events=Counter();ready=threading.Event();detached=threading.Event();errors=[];decisions=[];results=[];mutation_done=False
 session=None;handle=None;job=Job();identity_ok=False
 try:
  with Sink() as sink:
   configured_port=(sink.port%65535)+1 if mode=='wrong_peer' else sink.port
   script_text='const G75_CONFIG='+json.dumps({'port':configured_port})+';\n'+(BASE/'native_send_gate.js').read_text()
   device=frida.get_local_device()
   pid=device.spawn([str(exe),str(sink.port),str(inp),mode,'allow' if expected_calls else 'deny',str(marker)])
   job.assign(pid)
   expected_hash=hashlib.sha256(exe.read_bytes()).hexdigest()
   handle,_=guarded_process({'pid':pid,'image_path':str(exe),'sha256':expected_hash});identity_ok=True
   session=device.attach(pid);session.on('detached',lambda *args:detached.set())
   script=session.create_script(script_text)
   def message(msg,data):
    nonlocal mutation_done
    if msg.get('type')!='send':errors.append('script_error');return
    p=msg.get('payload',{});kind=p.get('kind');events[kind]+=1
    if kind=='native_script_ready':ready.set()
    if kind=='native_result':results.append(p)
    if kind=='native_hooks_installed':events['runtime_arch_matches']+=int(p.get('arch')==('ia32' if arch=='x86' else 'x64'))
    if kind=='candidate':
     reply={'allow':False,'reason':'controller_rejected'}
     try:
      if p.get('peer_exact_fixture') is True and type(p.get('id')) is int and data is not None and len(data)==p.get('bytes'):
       reply=admit_exact(policy,bytes(data))
      if mode=='mutate':
       marker.touch();deadline=time.monotonic()+3
       while not Path(str(marker)+'.done').exists() and time.monotonic()<deadline:time.sleep(.005)
       mutation_done=Path(str(marker)+'.done').exists()
       if not mutation_done:reply={'allow':False,'reason':'mutation_control_failed'}
      decisions.append({'allow':reply['allow'],'reason':reply['reason']})
      if mode=='bad_reply':reply={'allow':'true'}
      script.post({'type':'g75-admit-'+str(p['id']),'payload':reply})
     except Exception:
      errors.append('controller_error')
      try:script.post({'type':'g75-admit-'+str(p.get('id')),'payload':{'allow':False}})
      except Exception:pass
   script.on('message',message);script.load()
   if not ready.wait(5):raise RuntimeError('script_ready_timeout')
   device.resume(pid)
   if not detached.wait(12):raise RuntimeError('native_process_timeout')
   # A detached session is not by itself evidence that the process terminated.
   if K.WaitForSingleObject(handle,3000)!=0:raise RuntimeError('native_process_not_terminated')
   code=W.DWORD()
   if not K.GetExitCodeProcess(handle,C.byref(code)):raise RuntimeError('native_exit_query_failed')
   if not sink.done.wait(3):raise RuntimeError('sink_completion_timeout')
   actual=sink.receipts[0] if len(sink.receipts)==1 else None
   called=[r for r in results if r.get('original_called') is True]
   expected_results=2 if mode in ('split','tail') else 1
   approved_copy=all(r.get('approved_copy_used') is True and r['result']==len(want) for r in called)
   private_absent=actual is not None and b'PRIVATE_SENTINEL' not in actual
   passed=(identity_ok and code.value==0 and not errors and events['native_hooks_installed']==1 and
           events['runtime_arch_matches']==1 and len(results)==expected_results and len(called)==expected_calls and
           len(sink.receipts)==1 and sink.accepts==1 and actual==want and private_absent and approved_copy)
   if mode=='mutate':passed=passed and mutation_done
   row={'architecture':arch,'case':label,'passed':bool(passed),'process_identity_verified':identity_ok,
        'runtime_architecture_verified':events['runtime_arch_matches']==1,'native_exit_code':int(code.value),'original_send_calls':len(called),'native_result_count':len(results),
        'expected_original_send_calls':expected_calls,'TCP_connections_accepted':sink.accepts,
        'upstream_bytes_received':len(actual) if actual is not None else None,
        'receipt_exact_expected_public_bytes':actual==want,'synthetic_private_sentinel_absent':private_absent,
        'approved_snapshot_copy_used':approved_copy if called else None,
        'original_buffer_mutation_completed':mutation_done if mode=='mutate' else None,
        'denial_reasons':sorted({r.get('reason') for r in results if r.get('original_called') is False}),
        'policy_decisions':decisions,'script_errors':len(errors),'synthetic_only':True}
   return row
 finally:
  job.close()
  if handle:K.CloseHandle(handle)
  if session:
   try:session.detach()
   except Exception:pass
  for path in [inp,marker,Path(str(marker)+'.done')]:
   try:path.unlink()
   except FileNotFoundError:pass

def main():
 if os.name!='nt' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise RuntimeError('hosted_Windows_fixture_required')
 rows=[];error=None;stage='prepare';policy=load_policy(BASE)
 try:
  with tempfile.TemporaryDirectory(prefix='g75-native-',dir=os.environ['RUNNER_TEMP']) as d:
   tmp=Path(d);csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
   for arch in ['x86','x64']:
    stage='compile_'+arch;exe=tmp/('g75-native-'+arch+'.exe')
    r=subprocess.run([str(csc),'/nologo','/target:exe','/platform:'+arch,'/out:'+str(exe),str(BASE/'NativeSendFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    if r.returncode:raise RuntimeError('native_fixture_compile_failed')
    for case in vectors(BASE):
     stage=arch+'_'+case[0];row=run_case(exe,arch,policy,case,tmp);rows.append(row)
     if not row['passed']:raise RuntimeError('native_case_failed')
   stage=None
 except Exception as e:error=type(e).__name__
 result={'schema':'g75-native-pre-send-control-1','run_id':os.environ['GITHUB_RUN_ID'],'source_commit':os.environ['GITHUB_SHA'],
         'passed':len(rows)==48 and all(r['passed'] for r in rows) and error is None,
         'rows':rows,'error_type':error,'failure_stage':stage,'installer_started':False,'loopback_only':True,
         'firewall_changed':False,'certificate_trust_changed':False,'external_target_traffic':False,
         'transparent_client_compatibility_proven':False,'all_API_bypasses_closed':False,'TLS_supported':False,
         'raw_values_exported':False,'fingerprinting_absence_proven':False}
 out=Path('output');out.mkdir(exist_ok=True);(out/'g75-native-pre-send.json').write_text(json.dumps(result,indent=2))
 # One bounded public check annotation preserves redacted fixture receipts even
 # when artifact download requires a separate GitHub browser sign-in.
 print('::notice title=G75_NATIVE_EVIDENCE::'+json.dumps(result,separators=(',',':')))
 summary=os.environ.get('GITHUB_STEP_SUMMARY')
 if summary:
  with open(summary,'a') as f:f.write('## G75 native pre-send fixture\n\nPassed: '+str(result['passed'])+'; completed cases: '+str(len(rows))+'; failure stage: '+str(stage)+'\n\nLoopback-only, no installer/TLS/firewall changes. Full redacted cases in the G75_NATIVE_EVIDENCE check annotation and artifact.\n')
 if not result['passed']:raise SystemExit(1)
if __name__=='__main__':main()
