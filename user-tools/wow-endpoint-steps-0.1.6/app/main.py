import ctypes,json,os,secrets,subprocess,sys,threading,time,webbrowser
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from core import BASE,ENDPOINTS,REVIEW_ENDPOINTS,Session,atomic,firewall,selected_exe,validate,verify_package
from group import GroupSession as Session
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

def guard_start(p):
 child=subprocess.Popen([sys.executable,'-I',str(BASE/'app/main.py'),'--watchdog',str(p)],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),close_fds=True)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if p.with_suffix('.ready').exists() and child.poll() is None:return
  if child.poll() is not None:break
  time.sleep(.1)
 raise RuntimeError('watchdog_did_not_start')

def watchdog(p):
 j=validate(json.loads(p.read_text()))
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32];k.OpenProcess.restype=ctypes.c_void_p
 k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32];k.CloseHandle.argtypes=[ctypes.c_void_p]
 h=k.OpenProcess(0x00100000,False,j['parent_pid'])
 if not h:raise RuntimeError('parent_watch_failed')
 try:
  p.with_suffix('.ready').write_text('ready')
  deadline=time.monotonic()+max(0,min(300,j['expires']-time.time()))
  while p.exists() and time.monotonic()<deadline:
   if k.WaitForSingleObject(h,0)!=258:break
   time.sleep(1)
  # Delete only by exact journal identity; bounded retries are cleanup-only.
  for _ in range(6):
   if not p.exists():return
   try:
    firewall('remove',p);p.with_suffix('.restored').write_text('absence_verified');return
   except Exception:time.sleep(5)
 finally:k.CloseHandle(h)

LOCK=threading.RLock()
def serve(s):
 token=secrets.token_urlsafe(32)
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def send(self,code,obj,html=False):
   data=obj.encode('utf-8') if html else json.dumps(obj,ensure_ascii=False).encode('utf-8')
   self.send_response(code);self.send_header('Content-Type','text/html; charset=utf-8' if html else 'application/json; charset=utf-8');self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");self.end_headers();self.wfile.write(data)
  def authorized(self):
   return self.headers.get('Host')==self.server.authority and secrets.compare_digest(self.headers.get('X-WoW-Token',''),token) and (self.headers.get('Origin') in (None,'http://'+self.server.authority))
  def do_GET(self):
   if self.headers.get('Host')!=self.server.authority:return self.send(403,{'error':'invalid_host'})
   if self.path=='/':return self.send(200,(BASE/'app/ui.html').read_text('utf-8'),True)
   if not self.authorized():return self.send(403,{'error':'not_authorized'})
   with LOCK:
    if self.path=='/status':return self.send(200,{**s.status(),'endpoints':ENDPOINTS,'review_endpoints':REVIEW_ENDPOINTS})
   self.send(404,{'error':'not_found'})
  def do_POST(self):
   if not self.authorized():return self.send(403,{'error':'not_authorized'})
   try:
    n=int(self.headers.get('Content-Length','0'))
    if not 0<n<=8192:raise ValueError('invalid_request')
    x=json.loads(self.rfile.read(n))
    with LOCK:
     if self.path=='/pick':
      if s.phase!='idle':raise RuntimeError('restore_previous_first')
      s.program=selected_exe();from core import digest;s.hash=digest(s.program)
     elif self.path=='/start-group':s.start_group(x.get('consent'))
     elif self.path=='/start':s.start(x.get('index'),x.get('consent'))
     elif self.path=='/observe':s.observe(x.get('value'),x.get('fresh_launch_reported') is True)
     elif self.path=='/baseline':s.baseline(x.get('value'))
     elif self.path=='/restore':
      if s.current:s.restore('manual_stop')
      else:s.recover()
     elif self.path=='/exit':
      if s.current:s.restore('exit')
      s.recover();s.save();threading.Thread(target=self.server.shutdown,daemon=True).start()
     else:raise ValueError('invalid_request')
     self.send(200,{**s.status(),'endpoints':ENDPOINTS,'review_endpoints':REVIEW_ENDPOINTS})
   except Exception as e:
    code=str(e)
    if not code.replace('_','').isalnum() or len(code)>100:code='operation_failed_no_next_test'
    self.send(400,{'error':code})
 server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.authority='127.0.0.1:'+str(server.server_port)
 server.daemon_threads=True
 print('Open in your own browser:', 'http://'+server.authority+'/#'+token,flush=True)
 print('Keep this console open. Use Stop & Restore before closing the browser.',flush=True)
 webbrowser.open('http://'+server.authority+'/#'+token)
 try:server.serve_forever(poll_interval=.5)
 finally:
  server.server_close()
  with LOCK:
   try:
    if s.current:s.restore('server_exit')
    s.recover();s.save()
   except Exception:print('RESTORE NOT VERIFIED. Run Restore.cmd after this console closes.',flush=True)

def main():
 if os.name!='nt' or ctypes.sizeof(ctypes.c_void_p)!=8:raise RuntimeError('windows_x64_required')
 verify_package()
 if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('run_as_administrator')
 if len(sys.argv)==3 and sys.argv[1]=='--watchdog':
  p=Path(sys.argv[2]).resolve()
  if p.parent!=BASE/'private-state' or not p.name.startswith('session-'):raise RuntimeError('invalid_journal_location')
  return watchdog(p)
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p;k.CloseHandle.argtypes=[ctypes.c_void_p]
 mutex=k.CreateMutexW(None,False,'Local\\WoWEndpointStepsExclusive_01')
 if not mutex or ctypes.get_last_error()==183:raise RuntimeError('tool_already_running_close_it_before_Restore')
 try:
  from observer import start as monitor_start,stop as monitor_stop
  s=Session(guard=guard_start,monitor=monitor_start,monitor_stop=monitor_stop);s.recover()
  if '--restore' in sys.argv:print('Verified: no rules from this package journals remain.');return
  serve(s)
 finally:k.CloseHandle(mutex)
if __name__=='__main__':
 try:main()
 except Exception as e:
  code=str(e);print('Stopped:',code if len(code)<110 and code.replace('_','').isalnum() else 'operation_failed_Run_Restore_cmd',flush=True)
  sys.exit(1)
