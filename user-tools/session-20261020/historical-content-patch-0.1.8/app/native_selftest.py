import socket,subprocess,sys,threading,time
from pathlib import Path
from observer import ContentCollector

def run(frida,collector_type=ContentCollector,fixture_name='fixture.py'):
 if fixture_name not in {'fixture.py','game_fixture.py'}:raise ValueError('selftest_fixture_refused')
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(12)
 received=[];errors=[]
 def server():
  try:
   conn,_=listener.accept();conn.settimeout(8)
   with conn:
    b=b''
    while True:
     chunk=conn.recv(4096)
     if not chunk:break
     b+=chunk
     if len(b)>4096:raise ValueError('fixture_size')
    received.append(b)
  except Exception:errors.append('loopback_worker_failed')
 thread=threading.Thread(target=server,daemon=True);thread.start()
 worker=None;c=None
 result={'passed':False,'owned_loopback_only':True,'sspi_pre_tls_tested':False,'tls_decryption_tested':False,'error_code':None}
 try:
  worker=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name(fixture_name))],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
  c=collector_type(frida,{'cpu_model':['LOCAL-TEST-CPU'],'bios_version':['TEST123']},fixture_pid=worker.pid)
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   try:c.attach(worker.pid,'owned_fixture',fixture=True);break
   except OSError:time.sleep(.1)
  if not c.rows or not any(r['status']=='attached' and r['hook_ready'] for r in c.rows.values()):raise ValueError('fixture_attach_failed')
  worker.stdin.write((str(listener.getsockname()[1])+'\n').encode());worker.stdin.flush()
  deadline=time.monotonic()+10
  while time.monotonic()<deadline and not errors:
   with c.lock:
    if c.audit.count:break
   time.sleep(.1)
  thread.join(10);time.sleep(.3);c.close();a=c.audit_report()
  rows=a['requests'];ok=any(r['hardware_literal_matches']==['bios_version','cpu_model'] and r['remote_address']=='127.0.0.1' and r['body_complete'] for r in rows)
  result['passed']=bool(ok and received and not errors)
  if hasattr(c,'control_metadata'):
   result.update(c.control_metadata())
   result['passed']=result['passed'] and result['synthetic_clienthello_sni_observed'] and result['prefix_hook_observed']
  if not result['passed']:result['error_code']='fixture_content_or_destination_not_observed'
 except Exception as e:
  result['error_code']=str(e) if isinstance(e,ValueError) else 'fixture_failed'
 finally:
  if c:c.close()
  if worker:
   try:
    worker.stdin.write(b'END\n');worker.stdin.flush();worker.wait(timeout=3)
   except Exception:
    if worker.poll() is None:worker.kill();worker.wait(timeout=3)
  listener.close();thread.join(1)
 return result
