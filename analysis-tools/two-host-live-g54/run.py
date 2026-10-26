"""Fresh hosted Windows only. Bounded startup, no login/game install/UI automation."""
import os,sys,json,time,threading,subprocess,socket,ipaddress
from pathlib import Path
from collections import Counter
import frida
from content import Inspector,TARGETS
from Job import Job
from probe import inspect as probe_ui
base=Path(__file__).resolve().parent;root=Path(os.environ['RUNNER_TEMP'])/'g54-private'
if os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('BNET_G54')!='approved-live-startup-two-hosts-g54':raise SystemExit('hosted_approval_required')
def ps(action):
 r=subprocess.run(['powershell.exe','-NoProfile','-File',str(base/'Gate.ps1'),'-Action',action,'-Root',str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
 if r.returncode:raise RuntimeError('gate_'+action.lower()+'_failed')
root.mkdir(exist_ok=False)
report={'schema':'two-host-live-g54-1','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'scope':'bounded_signed_bootstrap_startup_with_read_only_UI_probe_no_UI_advance_no_login_not_full_download','installer_executed':False,'firewall_verified':False,'error':None,'cleanup':False,'fingerprinting_absence_proven':False}
inspector=Inspector();counts=Counter();sessions=[];known_pids=set();snapshots=[];lock=threading.RLock();device=None;job=None;armed=False;errors=[];peer_unknown=0
try:
 control=json.loads(Path('output/g54-native-control.json').read_text())
 if control.get('passed') is not True or control.get('source_commit')!=os.environ['GITHUB_SHA'] or control.get('run_id')!=os.environ['GITHUB_RUN_ID']:raise RuntimeError('native_positive_control_required')
 report['native_control_passed']=True
 ps('Prepare')
 config=json.loads((root/'config.json').read_text(encoding='utf-8-sig'));ips={ipaddress.ip_address(x) for x in config['ips']}
 job=Job();device=frida.get_local_device();hook=(base/'hook.js').read_text()
 def attach(pid):
  session=device.attach(pid);sessions.append(session);known_pids.add(pid);session.enable_child_gating();script=session.create_script(hook);ready=threading.Event()
  def message(m,data):
   with lock:
    if m.get('type')!='send':counts['hook_script_error']+=1;return
    p=m['payload'];k=p.get('kind','unknown');counts[k]+=1
    if k=='ready':ready.set()
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
     if accepted:inspector.feed((pid,p['socket']),bytes(data))
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
 pid=device.spawn([str(root/'Battle.net-Setup.exe')]);job.assign(pid);attach(pid)
 device.resume(pid);report['installer_executed']=True
 start=time.monotonic();next_probe=5
 while time.monotonic()-start<90:
  time.sleep(1)
  elapsed=time.monotonic()-start
  if elapsed>=next_probe:
   with lock: scoped=set(known_pids)
   snapshots.append({'elapsed_seconds':round(elapsed,1),'probe':probe_ui(scoped)})
   next_probe+=20
  with lock:
   if counts['hook_script_error'] or counts['child_attach_failure'] or inspector.capped:break
 report['observed_seconds']=round(time.monotonic()-start,1)
except Exception as e:
 m=str(e);report['error']=m if m.replace('_','').isalnum() and len(m)<90 else type(e).__name__
finally:
 if job:
  try:job.close()
  except Exception:report['job_cleanup_failed']=True
 # Retain blocking until target processes have exited. Restore only on a fresh disposable runner.
 try:ps('Restore');report['cleanup']=True
 except Exception:report['cleanup']=False;report['restore_error']='restore_refused_or_failed'
 with lock:report['content']=inspector.report();report['hook_counts']=dict(counts);report['read_only_UI_snapshots']=snapshots
 report['hosts']={h:{'request_rows':sum(r['host']==h for r in inspector.rows),'verdict':'bounded_observation_only' if any(r['host']==h for r in inspector.rows) else 'unknown_no_content_rows'} for h in TARGETS}
 report['coverage_complete']=False;report['server_receipt_proven']=False;report['hook_changes_client_timing_possible']=True
 out=Path('output');out.mkdir(exist_ok=True);(out/'two-host-live-g54.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 print('G54_SANITIZED='+json.dumps(report))
if report['error'] or not report['cleanup']:raise SystemExit(1)
