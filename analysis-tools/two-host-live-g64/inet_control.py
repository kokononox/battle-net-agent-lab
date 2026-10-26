"""Exact synthetic WinINet input and receiving-server controls on loopback only."""
import os,json,threading,subprocess
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
import frida
from Job import Job
from inet_content import classify
BASE=Path(__file__).resolve().parent
BODY=b'device=synthetic-control'
RESPONSE=b'G64-RESPONSE-PLAIN'
def run_inet(arch,wide=False):
 suffix='W' if wide else 'A'
 received=[]
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_POST(self):
   body=self.rfile.read(int(self.headers.get('Content-Length','0')));received.append((self.path,body))
   self.send_response(200);self.send_header('Content-Length',str(len(RESPONSE)));self.end_headers();self.wfile.write(RESPONSE)
 server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();port=server.server_address[1]
 exe=Path(os.environ['RUNNER_TEMP'])/('g64-inet-'+arch+suffix+'.exe');csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 built=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/('InetFixtureW.cs' if wide else 'InetFixture.cs'))],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
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
  good=len(events)==1 and not errors
  if good:
   p,b=events[0];good=p['server']=='127.0.0.1' and p['port']==port and p['method']=='POST' and p['path']=='/agent/versions?fixture=1' and p['api_returned_true'] and b==BODY and p['body_observed_complete']
   row=classify(p,b,allow_fixture=True);good=good and row['hardware_field_name_hint'] and row['query_present']
  server_exact=received==[('/agent/versions?fixture=1',BODY)]
  response_ok=any(p['api']=='InternetReadFile' and b==RESPONSE[:5] for p,b in responses) and any(p['api']=='InternetReadFileEx'+suffix and b==RESPONSE[5:] for p,b in responses)
  begin_ok=len(begun)==1 and begun[0][1]==BODY and len(events)==1 and begun[0][0]['call_id']==events[0][0]['call_id']
  diagnostic_ok=all(any(x['api']==api+suffix and x['succeeded'] for x in diagnostics) for api in ['InternetOpen','InternetConnect','HttpOpenRequest'])
  good=good and response_ok and begin_ok and diagnostic_ok
  return {'architecture':arch,'control':'WinINet_'+suffix+'_HTTP_loopback','passed':bool(good and server_exact),'native_request_rows':len(events),'begin_and_completion_linked':bool(begin_ok),'response_plaintext_exact':bool(response_ok),'response_API_events':len(responses),'startup_diagnostic_control_passed':bool(diagnostic_ok),'TLS_fixture_executed':False,'receiving_server_exact':server_exact,'script_errors':len(errors),'script_error_kinds':sorted(set(errors)),'synthetic_only':True,'included_in_real_report':False}
 finally:
  job.close();server.shutdown();server.server_close()
  if session:
   try:session.detach()
   except Exception:pass
  try:exe.unlink()
  except OSError:pass
