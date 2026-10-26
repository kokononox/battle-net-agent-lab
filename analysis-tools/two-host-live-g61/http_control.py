"""Exact synthetic WinINet input and receiving-server controls on loopback only."""
import os,json,threading,subprocess
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
import frida
from Job import Job
from inet_content import classify
BASE=Path(__file__).resolve().parent
BODY=b'device=synthetic-control'
RESPONSE=b'G61-RESPONSE-PLAIN'
def run_http(arch):
 received=[]
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_POST(self):
   body=self.rfile.read(int(self.headers.get('Content-Length','0')));received.append((self.path,body))
   self.send_response(200);self.send_header('Content-Length',str(len(RESPONSE)));self.end_headers();self.wfile.write(RESPONSE)
 server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();port=server.server_address[1]
 exe=Path(os.environ['RUNNER_TEMP'])/('g61-http-'+arch+'.exe');csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 built=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/'HttpFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('inet_fixture_compile_failed')
 device=frida.get_local_device();job=Job();session=None;ready=threading.Event();done=threading.Event();events=[];begun=[];responses=[];errors=[];diagnostics=[]
 try:
  pid=device.spawn([str(exe),str(port)]);job.assign(pid);session=device.attach(pid);session.on('detached',lambda *a:done.set());script=session.create_script((BASE/'hook.js').read_text())
  def message(m,data):
   if m.get('type')!='send':
    text=m.get('description','')
    errors.append('access_violation' if 'access violation' in text.lower() else 'type_error' if 'TypeError' in text else 'other_script_error');return
   p=m['payload']
   if p.get('kind')=='ready':ready.set()
   if p.get('kind')=='startup_diagnostic':diagnostics.append(p)
   if p.get('kind')=='wininet_request_input':events.append((p,bytes(data or b'')))
   if p.get('kind')=='wininet_request_begun':begun.append((p,bytes(data or b'')))
   if p.get('kind')=='wininet_response_bytes':responses.append((p,bytes(data or b'')))
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('inet_observer_not_ready')
  device.resume(pid)
  if not done.wait(20):raise RuntimeError('inet_fixture_timeout')
  expected={'WinHttpSendRequest':b'device=','WinHttpWriteData':b'synthetic-control'}
  good=len(events)==2 and len(begun)==2 and not errors
  for p,b in events:
   good=good and p.get('api') in expected and b==expected[p['api']] and p['server']=='127.0.0.1' and p['port']==port and p['method']=='POST' and p['api_returned_true'] and p['body_observed_complete']
   row=classify(p,b,allow_fixture=True);good=good and row['query_present'] and row['layer']=='WinHTTP_API_input_not_wire_receipt'
  begin_ok={(p['call_id'],b) for p,b in begun}=={(p['call_id'],b) for p,b in events} and len(begun)==2
  response_ok=any(p['api']=='WinHttpReadData' and b==RESPONSE for p,b in responses)
  server_exact=received==[('/agent/versions?fixture=1',BODY)]
  diagnostic_ok=all(any(x['api']==api and x['succeeded'] for x in diagnostics) for api in ['WinHttpOpen','WinHttpConnect','WinHttpOpenRequest'])
  good=good and diagnostic_ok
  return {'architecture':arch,'control':'WinHTTP_HTTP_loopback','passed':bool(good and begin_ok and response_ok and server_exact),'native_API_input_rows':len(events),'begin_and_completion_linked':bool(begin_ok),'response_plaintext_exact':bool(response_ok),'response_API_events':len(responses),'startup_diagnostic_control_passed':bool(diagnostic_ok),'TLS_fixture_executed':False,'receiving_server_exact':server_exact,'script_errors':len(errors),'script_error_kinds':sorted(set(errors)),'synthetic_only':True,'included_in_real_report':False}

 finally:
  job.close();server.shutdown();server.server_close()
  if session:
   try:session.detach()
   except Exception:pass
  try:exe.unlink()
  except OSError:pass
