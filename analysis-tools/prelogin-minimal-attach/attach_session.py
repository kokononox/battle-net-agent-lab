"""Attach to an already-owned running process. Fixed readiness script; no hooks."""
import threading
SOURCE="send({kind:'ready',pointer_bits:Process.pointerSize*8});"
ERRORS={None,'OSError','ValueError','RuntimeError','ProcessNotFoundError','PermissionDeniedError','InvalidOperationError','TimedOutError','OperationCancelledError','TransportError','other'}
def kind(exc):return type(exc).__name__ if type(exc).__name__ in ERRORS else 'other'
def blank():return dict(status='not_started',attach_returned=False,image_verified_before_and_after=False,ready=False,pointer_bits=None,bitness_confirmed=False,message_errors=0,error_kind=None)
def bounded(frida,call):
 cancel=frida.Cancellable();timer=threading.Timer(8,cancel.cancel);timer.daemon=True;timer.start()
 try:
  with cancel:return call()
 finally:timer.cancel()
class Session:
 def __init__(self,frida,device):
  self.frida=frida;self.device=device;self.session=None;self.script=None;self.record=blank();self.signal=threading.Event();self.lock=threading.Lock()
 def message(self,msg,data):
  with self.lock:
   p=msg.get('payload') if type(msg) is dict else None
   if data is not None or type(msg) is not dict or msg.get('type')!='send' or type(p) is not dict or set(p)!={'kind','pointer_bits'} or p['kind']!='ready' or type(p['pointer_bits']) is not int or p['pointer_bits'] not in (32,64) or self.record['ready']:
    self.record['message_errors']=min(128,self.record['message_errors']+1);self.signal.set();return
   self.record['ready']=True;self.record['pointer_bits']=p['pointer_bits'];self.signal.set()
 def start(self,pid,verify,expected_bits):
  try:
   if expected_bits not in (32,64):raise ValueError('bitness')
   verify();self.session=bounded(self.frida,lambda:self.device.attach(pid));self.record['attach_returned']=True
   self.script=bounded(self.frida,lambda:self.session.create_script(SOURCE));self.script.on('message',self.message)
   bounded(self.frida,self.script.load)
   if not self.signal.wait(3) or not self.record['ready'] or self.record['message_errors']:raise RuntimeError('readiness')
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
