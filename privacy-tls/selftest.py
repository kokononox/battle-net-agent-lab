"""Owned synthetic worker only; loopback port 1, no proxy and no real-client data."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from body_meta import analyze_body

def worker(folder):
 root=Path(folder);w=ctypes.WinDLL('winhttp',use_last_error=True)
 ptr=ctypes.c_void_p;u=ctypes.c_uint32;txt=ctypes.c_wchar_p
 w.WinHttpOpen.argtypes=[txt,u,txt,txt,u];w.WinHttpOpen.restype=ptr
 w.WinHttpConnect.argtypes=[ptr,txt,ctypes.c_uint16,u];w.WinHttpConnect.restype=ptr
 w.WinHttpOpenRequest.argtypes=[ptr,txt,txt,txt,txt,ptr,u];w.WinHttpOpenRequest.restype=ptr
 w.WinHttpSendRequest.argtypes=[ptr,txt,u,ptr,u,u,ctypes.c_size_t];w.WinHttpSendRequest.restype=ctypes.c_int
 w.WinHttpSetTimeouts.argtypes=[ptr,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int]
 w.WinHttpCloseHandle.argtypes=[ptr]
 (root/'ready').write_text('ready')
 start=time.monotonic()
 while not (root/'go').exists() and time.monotonic()-start<30:time.sleep(.05)
 if not (root/'go').exists():return
 session=w.WinHttpOpen('SyntheticLoopbackTest',1,None,None,0)
 conn=w.WinHttpConnect(session,'127.0.0.1',1,0)
 req=w.WinHttpOpenRequest(conn,'POST','/synthetic',None,None,None,0)
 w.WinHttpSetTimeouts(req,500,500,500,500)
 body=b'{"cpu":"SYNTHETIC_VALUE_NOT_REAL_HARDWARE"}';buf=ctypes.create_string_buffer(body)
 w.WinHttpSendRequest(req,None,0,buf,len(body),len(body),0)
 for handle in (req,conn,session):
  if handle:w.WinHttpCloseHandle(handle)
 time.sleep(1)
 (root/'done').write_text('done')

def run_selftest(frida,env):
 result={'passed':False,'stage':'not_started','loopback_only':True,'synthetic_events_excluded_from_real_evidence':True}
 session=None;process=None;events=[]
 def bounded(fn):
  c=frida.Cancellable();timer=threading.Timer(8,c.cancel);timer.daemon=True;timer.start()
  try:return fn(c)
  finally:timer.cancel()
 def message(msg,data):
  if msg.get('type')=='send' and isinstance(msg.get('payload'),dict):
   d=msg['payload']
   if d.get('kind')=='buffer' and d.get('api')=='WinHttpSendRequest':events.append(analyze_body(bytes(data or b''),d.get('declared_length',0),d.get('readable') is True))
 try:
  with tempfile.TemporaryDirectory(prefix='tls-loopback-test-',dir=os.environ['RUNNER_TEMP']) as folder:
   root=Path(folder);result['stage']='worker_start'
   process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--worker',folder],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   until=time.monotonic()+10
   while not (root/'ready').exists() and time.monotonic()<until:time.sleep(.05)
   if not (root/'ready').exists():return result
   result['stage']='attach';session=bounded(lambda c:frida.get_local_device().attach(process.pid,cancellable=c))
   result['stage']='script_load';script=session.create_script(Path(__file__).with_name('hook.js').read_text());script.on('message',message);bounded(lambda c:script.load(cancellable=c))
   (root/'go').write_text('go');result['stage']='await_event';until=time.monotonic()+8
   while not (root/'done').exists() and time.monotonic()<until:time.sleep(.05)
   result['passed']=any(e['format']=='json' and 'cpu' in e['field_name_hints'] for e in events)
   result['stage']='complete' if result['passed'] else 'event_not_observed'
 except Exception:pass
 finally:
  if session is not None:
   try:bounded(lambda c:session.detach(cancellable=c))
   except Exception:pass
  if process is not None:
   if process.poll() is None:process.kill()
   try:process.wait(timeout=5)
   except Exception:pass
 return result
if __name__=='__main__' and sys.argv[1:2]==['--worker']:worker(sys.argv[2])
