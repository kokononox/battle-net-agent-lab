"""One synthetic isolation case. Error case intentionally exits abruptly."""
import json,os,queue,subprocess,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import context,save,read,wait_file,gate,ROOT
import native as n

KEEP={'SYSTEMROOT','WINDIR','SYSTEMDRIVE','ALLUSERSPROFILE','PROGRAMDATA','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMW6432','COMSPEC','PATH'}
def clean_env():return {k:v for k,v in os.environ.items() if k.upper() in KEEP}
def start_component(c,role,job):
 child=subprocess.Popen([sys.executable,'-I',str(ROOT/'component.py'),role,c['root']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=clean_env())
 try:n.assign(job,child)
 except BaseException:child.kill();child.wait();raise
 child.stdin.write(b'x');child.stdin.flush();return child
class Channel:
 def __init__(self,child):
  self.child=child;self.lines=queue.Queue()
  def pump():
   for line in child.stdout:self.lines.put(line)
   self.lines.put(None)
  threading.Thread(target=pump,daemon=True).start()
 def response(self):
  raw=self.lines.get(timeout=12)
  if raw is None:raise RuntimeError('fixture_exited')
  return json.loads(raw)
 def send(self,op):
  self.child.stdin.write((json.dumps({'op':op})+'\n').encode());self.child.stdin.flush()
  return self.response()

def run(root):
 c=context(root);root=Path(root);job=n.create_job(c['job_name']);watchdog=None
 r={'mode':c['mode'],'baseline_connected':False,'blocked_connected':None,'gate_before':False,'gate_after':False,'capture_blocked':False,'private_capture_stored':False,'private_marker_retained':False,'public_marker_absent':False,'credential_redacted':False,'fixture_alive_during_gate':False,'error_code':None}
 try:
  c['controller']=n.identity();save(root/'config.json',c)
  save(root/'peers.json',{'expires_unix':time.time()+300,'job_name':c['job_name'],'controller':c['controller']});save(root/'lease.json',{'phase':'active'})
  server=start_component(c,'server',job);wait_file(root/'endpoint.json')
  client=start_component(c,'client',job);channel=Channel(client)
  if channel.response().get('ready') is not True:raise RuntimeError('client_not_ready')
  r['baseline_connected']=channel.send('probe')['connected']
  if not r['baseline_connected']:raise RuntimeError('baseline_not_healthy')
  gate(c,'Prepare')
  watchdog=subprocess.Popen([sys.executable,'-I',str(ROOT/'recovery.py'),'watchdog',str(root)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=clean_env())
  # Store native identity, not only PID, for parent proof of watchdog exit.
  h=n.K.OpenProcess(0x1000|0x100000,False,watchdog.pid)
  if not h:raise RuntimeError('watchdog_identity_failed')
  try:
   from ctypes import wintypes as W
   import ctypes as C
   ft=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
   if not n.K.GetProcessTimes(h,C.byref(ft),*[C.byref(v) for v in other]):raise RuntimeError('watchdog_identity_failed')
   c['watchdog_identity']={'pid':watchdog.pid,'created':(ft.dwHighDateTime<<32)|ft.dwLowDateTime}
  finally:n.K.CloseHandle(h)
  save(root/'config.json',c);wait_file(root/'watchdog-ready.json')
  before=gate(c,'Apply');r['gate_before']=before['verified'];r['management_exceptions']=before['management_exceptions']
  r['blocked_connected']=channel.send('probe')['connected'];r['fixture_alive_during_gate']=client.poll() is None and n.active(job)>=2
  if r['blocked_connected'] or not r['fixture_alive_during_gate']:raise RuntimeError('direct_egress_not_blocked')
  r['capture_blocked']=channel.send('capture')['blocked'];receipt=wait_file(root/'capture-receipt.json')
  r['private_capture_stored']=receipt['private_stored'];r['public_marker_absent']='SYNTHETIC-G41-DEVICE' not in json.dumps(receipt)
  from windows_store import WindowsStore
  record=WindowsStore(root/'quarantine',c['helper']).read_for_local_review(receipt['capture_id'])
  r['private_marker_retained']='SYNTHETIC-G41-DEVICE' in record['query'];r['credential_redacted']='SYNTHETIC-SECRET' not in json.dumps(record)
  if not all(r[k] for k in ('capture_blocked','private_capture_stored','public_marker_absent','private_marker_retained','credential_redacted')):raise RuntimeError('quarantine_failed')
  r['gate_after']=gate(c,'Verify')['verified'];save(root/'case-result.json',r)
  if c['mode']=='error':os._exit(23) # No release request or Python finally cleanup.
  if c['mode']=='finish':
   client.stdin.write(b'{"op":"exit"}\n');client.stdin.flush();client.wait(timeout=10)
  save(root/'release-request.json',{'reason':c['mode']})
  wait_file(root/'recovery-result.json',100);watchdog.wait(timeout=15)
  return 0
 except Exception as exc:
  reason=str(exc);r['error_code']=reason if reason.replace('_','').isalpha() and len(reason)<80 else 'coordinator_failed'
  save(root/'case-result.json',r)
  if watchdog is not None:save(root/'release-request.json',{'reason':'fallback'});wait_file(root/'recovery-result.json',100)
  else:
   # No mutation occurs before watchdog exists. Still stop known owned fixture.
   n.end_job(job)
  return 2
 finally:
  n.K.CloseHandle(job)
if __name__=='__main__':raise SystemExit(run(sys.argv[1]))
