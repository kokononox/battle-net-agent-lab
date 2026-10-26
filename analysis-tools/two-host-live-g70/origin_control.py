"""Native controlled positive provenance: one disk and two socket-read APIs."""
import os,socket,threading,subprocess,time
from pathlib import Path
import frida
from Job import Job
from origin_audit import OriginAudit
BASE=Path(__file__).resolve().parent
K2=b'123456789abcdef0123456789abcdef0';K3=b'23456789abcdef0123456789abcdef01'
def run_origin(arch):
 exe=Path(os.environ['RUNNER_TEMP'])/('g70-origin-'+arch+'.exe');file=exe.with_suffix('.bin')
 csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 r=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/'OriginFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if r.returncode:raise RuntimeError('origin_fixture_compile_failed')
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(15);port=listener.getsockname()[1];received=[];server_errors=[]
 def serve():
  try:
   conn,_=listener.accept();conn.settimeout(15)
   with conn:
    for nextkey in (K2,K3,None):
     b=b''
     while not b.endswith(b'\r\n\r\n'):
      x=conn.recv(4096)
      if not x:raise RuntimeError('short_request')
      b+=x
     received.append(b)
     if nextkey:conn.sendall(nextkey)
  except Exception as e:server_errors.append(type(e).__name__)
 worker=threading.Thread(target=serve,daemon=True);worker.start();job=Job();session=None;ready=threading.Event();done=threading.Event();errors=[];trace=OriginAudit();gaps=[]
 try:
  device=frida.get_local_device();pid=device.spawn([str(exe),str(port),str(file)]);job.assign(pid);session=device.attach(pid);session.on('detached',lambda *a:done.set());script=session.create_script((BASE/'hook.js').read_text())
  def message(m,data):
   if m.get('type')!='send':errors.append('script_error');return
   p=m['payload'];k=p.get('kind')
   if k=='ready':ready.set()
   if k=='origin_gap':gaps.append(p.get('reason'))
   if k=='origin_source' and data:
    src=p.get('source')
    if src=='disk_ReadFile_sync':trace.source(('file',p['file_handle']),data,src,p.get('frames',[]))
    elif src in ('recv','WSARecv_immediate'):
     peer=p.get('peer') or {}
     if peer.get('ip')=='127.0.0.1' and peer.get('port')==port:trace.source(('socket',p['socket']),data,'selected_two_host_'+src,p.get('frames',[]))
   if k=='bytes' and data:trace.requests(('socket',p['socket']),data,p.get('origin_frames',[]))
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('origin_control_not_ready')
  device.resume(pid)
  if not done.wait(20):raise RuntimeError('origin_control_timeout')
  worker.join(2);rows=trace.report()['targets'];expected=('disk_ReadFile_sync','selected_two_host_recv','selected_two_host_WSARecv_immediate')
  good=len(rows)==3 and len(received)==3 and not errors and not server_errors
  for row,kind in zip(rows,expected):good=good and any(x['source_kind']==kind and x['preceded_request_observation'] for x in row['occurrences']) and bool(row['request_frames'])
  return {'architecture':arch,'control':'native_prior_key_occurrence','passed':bool(good),'targets':rows,'script_errors':len(errors),'server_errors':server_errors,'synthetic_only':True,'included_in_real_report':False,'external_network_used':False}
 finally:
  job.close();listener.close()
  if session:
   try:session.detach()
   except Exception:pass
  for p in (exe,file):
   try:p.unlink()
   except OSError:pass
