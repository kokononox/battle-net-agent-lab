"""Attach to an already-owned running process. Fixed-key registry-only script; no wire hooks."""
import threading,json
from pathlib import Path
from registry_events import Events,APIS
SOURCE="send({kind:'ready',pointer_bits:Process.pointerSize*8});"
ERRORS={None,'OSError','ValueError','RuntimeError','ProcessNotFoundError','PermissionDeniedError','InvalidOperationError','TimedOutError','OperationCancelledError','TransportError','other'}
def kind(exc):return type(exc).__name__ if type(exc).__name__ in ERRORS else 'other'
def blank():return dict(status='not_started',attach_returned=False,image_verified_before_and_after=False,ready=False,pointer_bits=None,bitness_confirmed=False,message_errors=0,error_kind=None,registry_ready=False)
def bounded(frida,call):
 cancel=frida.Cancellable();timer=threading.Timer(8,cancel.cancel);timer.daemon=True;timer.start()
 try:
  with cancel:return call()
 finally:timer.cancel()
class Session:
 def __init__(self,frida,device,image_path,digest):
  self.image_path=str(Path(image_path).resolve());self.digest=digest;self.registry=Events();self.regsignal=threading.Event();self.row=None;self.regbits=None
  self.frida=frida;self.device=device;self.session=None;self.script=None;self.record=blank();self.signal=threading.Event();self.lock=threading.Lock()
 def message(self,msg,data):
  with self.lock:
   p=msg.get('payload') if type(msg) is dict else None
   if type(p) is dict and str(p.get('kind','')).startswith('reg_'):
    try:
     if msg.get('type')!='send':raise ValueError('message_type')
     k=p['kind']
     if k!='reg_value' and data is not None:raise ValueError('unexpected_bytes')
     if k in ('reg_error','reg_limit') and set(p)!={'kind'}:raise ValueError('fields')
     if k=='reg_ready' and (type(p.get('pointer_bits')) is not int or p['pointer_bits'] not in (32,64)):raise ValueError('bits')
     self.registry.accept(self.row,p,data)
     if k=='reg_ready':
      if self.regbits is not None:raise ValueError('duplicate_readiness')
      self.regbits=p['pointer_bits'];self.regsignal.set()
    except Exception:self.registry.errors+=1
    return
   if data is not None or type(msg) is not dict or msg.get('type')!='send' or type(p) is not dict or set(p)!={'kind','pointer_bits'} or p['kind']!='ready' or type(p['pointer_bits']) is not int or p['pointer_bits'] not in (32,64) or self.record['ready']:
    self.record['message_errors']=min(128,self.record['message_errors']+1);self.signal.set();return
   self.record['ready']=True;self.record['pointer_bits']=p['pointer_bits'];self.signal.set()
 def start(self,pid,verify,expected_bits):
  try:
   if expected_bits not in (32,64):raise ValueError('bitness')
   self.row=dict(pid=pid,sha256=self.digest)
   verify();self.session=bounded(self.frida,lambda:self.device.attach(pid));self.record['attach_returned']=True
   self.script=bounded(self.frida,lambda:self.session.create_script('globalThis.__LAB_IMAGE_PATH='+json.dumps(self.image_path)+';\n'+(Path(__file__).resolve().parent.parent/'prelogin-registry-stack'/'registry_hook.js').read_text()+'\n'+SOURCE));self.script.on('message',self.message)
   bounded(self.frida,self.script.load)
   if not self.signal.wait(3) or not self.record['ready'] or self.record['message_errors']:raise RuntimeError('readiness')
   if not self.regsignal.wait(3) or pid not in self.registry.ready or self.regbits!=self.record['pointer_bits'] or self.registry.errors or self.registry.limits or not APIS<=self.registry.installed.get(pid,set()):raise RuntimeError('registry_readiness')
   self.record['registry_ready']=True
   verify();self.record['image_verified_before_and_after']=True
   self.record['bitness_confirmed']=self.record['pointer_bits']==expected_bits
   if not self.record['bitness_confirmed']:raise RuntimeError('bitness')
   self.record['status']='ready'
  except Exception as exc:self.record.update(status='failed',error_kind=kind(exc))
  return self.record
 def close(self):
  if self.session is not None:
   try:bounded(self.frida,self.session.detach)
   except Exception:pass

 def summary(self):
  with self.lock:
   r=self.registry.summary(set())
   for row in r['records']:del row['equals_wire_host_id']
   r['wire_comparison_performed']=False
   return r
