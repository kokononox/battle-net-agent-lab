"""Owned loopback worker only; never launches or terminates any Blizzard process."""
import ctypes
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from core import clean_env
from request_audit import AuditCollector as Collector,validate_audit

BODY=b'{"cpu":"SYNTHETIC_OBSERVER_FIXTURE_NOT_REAL_HARDWARE"}'
def packet():return b'POST /tpr/fixture?deviceid=NEVER_EXPORT_QUERY HTTP/1.1\r\nHost: level3.blizzard.com\r\nCookie: NEVER_EXPORT_COOKIE\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\n\r\n'+BODY

def worker(folder,port):
    folder=Path(folder)
    (folder/'ready').write_text('ready')
    deadline=time.monotonic()+25
    while not (folder/'go').exists() and time.monotonic()<deadline:time.sleep(.03)
    if not (folder/'go').exists():return
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        s.sendall(packet());s.recv(512)
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        raw=packet()
        class B(ctypes.Structure):_fields_=[('n',ctypes.c_uint32),('p',ctypes.c_void_p)]
        parts=[ctypes.create_string_buffer(raw[:17]),ctypes.create_string_buffer(raw[17:])]
        a=(B*2)(*[B(len(p.value),ctypes.cast(p,ctypes.c_void_p)) for p in parts]);sent=ctypes.c_uint32()
        fn=ctypes.WinDLL('ws2_32').WSASend;fn.argtypes=[ctypes.c_size_t,ctypes.POINTER(B),ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32,ctypes.c_void_p,ctypes.c_void_p];fn.restype=ctypes.c_int
        if fn(s.fileno(),a,2,ctypes.byref(sent),0,None,None)!=0 or sent.value!=len(raw):return
        s.recv(512)
    u=ctypes.c_uint32;ptr=ctypes.c_void_p
    class SecBuffer(ctypes.Structure):_fields_=[('n',u),('kind',u),('p',ptr)]
    class Desc(ctypes.Structure):_fields_=[('version',u),('count',u),('buffers',ctypes.POINTER(SecBuffer))]
    buf=ctypes.create_string_buffer(packet());b=SecBuffer(len(packet()),1,ctypes.cast(buf,ptr));d=Desc(0,1,ctypes.pointer(b));ctx=(ctypes.c_size_t*2)()
    f=ctypes.WinDLL('secur32').EncryptMessage;f.argtypes=[ptr,u,ptr,u];f.restype=ctypes.c_int32
    try:f(ctypes.byref(ctx),0,ctypes.byref(d),0)
    except OSError:pass
    time.sleep(.4)
    (folder/'done').write_text('done')

def run(frida):
    result={'passed':False,'loopback_only':True,'send_observed':False,'wsasend_observed':False,'sspi_negative_input_observed':False,'fixture_excluded_from_real_report':True,'worker_exited':False,'script_errors':0,'error_code':None}
    received=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers.get('Content-Length','0'))));self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();collector=None;process=None
    try:
        with tempfile.TemporaryDirectory(prefix='observer-selftest-') as folder:
            process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).resolve()),'--worker',folder,str(server.server_port)],env=clean_env(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
            deadline=time.monotonic()+8
            while not (Path(folder)/'ready').exists() and time.monotonic()<deadline:time.sleep(.03)
            if not (Path(folder)/'ready').exists():raise ValueError('selftest_worker_not_ready')
            collector=Collector(frida,BODY,fixture_pid=process.pid)
            collector.attach(process.pid,'owned_fixture',fixture=True)
            if not all(x['status']=='attached' for x in collector.rows.values()):raise ValueError('selftest_attach_failed')
            (Path(folder)/'go').write_text('go')
            process.wait(timeout=15);result['worker_exited']=True;time.sleep(.3)
            collector.close();r=collector.report();events=r['events']
            audit=validate_audit(collector.audit_report());requests=audit['requests']
            encoded=json.dumps(audit)
            if any(secret in encoded for secret in ('NEVER_EXPORT_QUERY','NEVER_EXPORT_COOKIE','SYNTHETIC_OBSERVER_FIXTURE')):raise ValueError('audit_secret_export')
            if len(requests)!=2 or not all(x['body_complete'] and x['body_observed_bytes']==len(BODY) and x['cpu_literal_match'] and x['body_field_hints']==['cpu'] and x['query_field_hints']==['device_id'] and x['credential_header_present'] for x in requests):raise ValueError('audit_reconstruction_failed')
            if not any(s['channel'].startswith('ctx') and s['api_input_gap'] for s in audit['streams']):raise ValueError('failed_sspi_not_separated')
            for api,key in [('send','send_observed'),('WSASend','wsasend_observed')]:
                result[key]=any(x['api']==api and x['host_hint']=='level3.blizzard.com' and x['reference_cpu_literal_match'] is True and x['local_api_success'] for x in events)
            result['sspi_negative_input_observed']=any(x['api']=='EncryptMessage' and x['reference_cpu_literal_match'] is True and not x['local_api_success'] and x['return_code']!=0 for x in events)
            result['script_errors']=sum(x['script_errors'] for x in r['processes'])
            result['passed']=all(result[k] for k in ('send_observed','wsasend_observed','sspi_negative_input_observed','worker_exited')) and result['script_errors']==0 and received==[BODY,BODY]
    except Exception as exc:
        result['error_code']=str(exc) if isinstance(exc,ValueError) else 'owned_selftest_failed'
    finally:
        if collector:collector.close()
        # Only the worker created above may remain briefly; it has its own 25-second exit.
        # No kill/terminate API is ever used, including fixture cleanup.
        if process and process.poll() is None:
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:result['error_code']='owned_worker_exit_timeout'
        server.shutdown();server.server_close();thread.join(timeout=2)
    return result

if __name__=='__main__':worker(sys.argv[2],int(sys.argv[3]))
