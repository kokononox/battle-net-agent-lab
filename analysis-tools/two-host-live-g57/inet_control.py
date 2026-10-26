"""Exact synthetic WinINet input and receiving-server controls on loopback only."""
import os,json,threading,subprocess
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
import frida
from Job import Job
from inet_content import classify
BASE=Path(__file__).resolve().parent
BODY=b'device=synthetic-control'
def run_inet(arch):
 received=[]
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_POST(self):
   body=self.rfile.read(int(self.headers.get('Content-Length','0')));received.append((self.path,body))
   self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
 server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();port=server.server_address[1]
 exe=Path(os.environ['RUNNER_TEMP'])/('g57-inet-'+arch+'.exe');csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 built=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/'InetFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('inet_fixture_compile_failed')
 device=frida.get_local_device();job=Job();session=None;ready=threading.Event();done=threading.Event();events=[];errors=[]
 try:
  pid=device.spawn([str(exe),str(port)]);job.assign(pid);session=device.attach(pid);session.on('detached',lambda *a:done.set());script=session.create_script((BASE/'hook.js').read_text())
  def message(m,data):
   if m.get('type')!='send':errors.append('script_error');return
   p=m['payload']
   if p.get('kind')=='ready':ready.set()
   if p.get('kind')=='wininet_request_input':events.append((p,bytes(data or b'')))
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('inet_observer_not_ready')
  device.resume(pid)
  if not done.wait(20):raise RuntimeError('inet_fixture_timeout')
  good=len(events)==1 and not errors
  if good:
   p,b=events[0];good=p['server']=='127.0.0.1' and p['port']==port and p['method']=='POST' and p['path']=='/agent/versions?fixture=1' and p['api_returned_true'] and b==BODY and p['body_observed_complete']
   row=classify(p,b,allow_fixture=True);good=good and row['hardware_field_name_hint'] and row['query_present']
  server_exact=received==[('/agent/versions?fixture=1',BODY)]
  return {'architecture':arch,'control':'WinINet_HTTP_loopback','passed':bool(good and server_exact),'native_request_rows':len(events),'receiving_server_exact':server_exact,'script_errors':len(errors),'synthetic_only':True,'included_in_real_report':False}
 finally:
  job.close();server.shutdown();server.server_close()
  if session:
   try:session.detach()
   except Exception:pass
  try:exe.unlink()
  except OSError:pass
