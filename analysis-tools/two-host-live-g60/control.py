"""Native x86/x64 loopback positive control, strictly separate from real target report."""
import json,os,sys,socket,threading,time,subprocess,ipaddress
from pathlib import Path
from collections import Counter
import frida
from Job import Job
from content import Inspector
BASE=Path(__file__).resolve().parent
EXPECTED=b'GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\nGET /tpr/fixture HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n'
def run_one(arch):
 exe=Path(os.environ['RUNNER_TEMP'])/('g60-fixture-'+arch+'.exe')
 csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 result=subprocess.run([str(csc),'/nologo','/target:exe','/platform:'+arch,'/out:'+str(exe),str(BASE/'Fixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if result.returncode:raise RuntimeError('fixture_compile_failed')
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(15);port=listener.getsockname()[1];server=[];done=threading.Event()
 def receive():
  try:
   conn,_=listener.accept();conn.settimeout(10)
   with conn:
    while True:
     b=conn.recv(4096)
     if not b:break
     server.append(b)
  finally:done.set()
 worker=threading.Thread(target=receive,daemon=True);worker.start()
 device=frida.get_local_device();job=Job();session=None;inspector=Inspector();events=Counter();ready=threading.Event();detached=threading.Event();chunks=[];peers_ok=True;script_errors=0
 try:
  pid=device.spawn([str(exe),str(port)]);job.assign(pid);session=device.attach(pid)
  session.on('detached',lambda *a:detached.set())
  script=session.create_script((BASE/'hook.js').read_text())
  def message(m,data):
   nonlocal peers_ok,script_errors
   if m.get('type')!='send':script_errors+=1;return
   p=m['payload'];events[p['kind']]+=1
   if p['kind']=='ready':ready.set()
   if p['kind']=='bytes' and data:
    peer=p.get('peer');peers_ok &= bool(peer and ipaddress.ip_address(peer['ip']).is_loopback and peer['port']==port)
    events['api_'+str(p.get('api'))]+=1;chunks.append(bytes(data));inspector.feed('fixture',bytes(data))
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('fixture_observer_not_ready')
  device.resume(pid)
  if not done.wait(15) or not detached.wait(5):raise RuntimeError('fixture_timeout')
  passed=b''.join(server)==EXPECTED and b''.join(chunks)==EXPECTED and peers_ok and script_errors==0 and events['api_send']==1 and events['api_WSASend']==1 and len(inspector.rows)==2 and events['hooks_installed']==1
  return {'architecture':arch,'passed':passed,'server_received_exact_fixture':b''.join(server)==EXPECTED,'observer_received_exact_fixture':b''.join(chunks)==EXPECTED,'peer_exact_loopback_port':bool(peers_ok),'events':dict(events),'script_errors':script_errors,'request_rows':len(inspector.rows),'synthetic_only':True,'included_in_real_report':False}
 finally:
  job.close();listener.close()
  if session:
   try:session.detach()
   except Exception:pass
  try:exe.unlink()
  except OSError:pass
if __name__=='__main__':
 if os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('hosted_required')
 rows=[];error=None
 try:
  for arch in ['x86','x64']:rows.append(run_one(arch))
  from inet_control import run_inet
  for wide in [False,True]:
   for arch in ['x86','x64']:rows.append(run_inet(arch,wide))
  from http_control import run_http
  for arch in ['x86','x64']:rows.append(run_http(arch))
 except Exception as e:error=type(e).__name__
 out=Path('output');out.mkdir(exist_ok=True)
 r={'schema':'g60-native-control-1','run_id':os.environ['GITHUB_RUN_ID'],'source_commit':os.environ['GITHUB_SHA'],'passed':len(rows)==8 and all(x['passed'] for x in rows) and error is None,'rows':rows,'error_type':error,'external_network_used_by_fixture':False}
 (out/'g60-native-control.json').write_text(json.dumps(r,indent=2));print('G60_CONTROL='+json.dumps(r))
 if not r['passed']:raise SystemExit(1)
