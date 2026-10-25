"""Independent process recovery. No unconditional firewall release."""
import ctypes as C,json,os,sys,time
from pathlib import Path
from ctypes import wintypes as W
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import context,save,read,gate
import native as n
import peer_guard as peer
K=n.K
K.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE];K.CreateFileW.restype=W.HANDLE
INVALID=C.c_void_p(-1).value

def recover(c,reason,job=None):
 root=Path(c['root']);lock=None;own=False
 end=time.monotonic()+30
 while time.monotonic()<end:
  lock=K.CreateFileW(str(root/'recovery.lock'),0xc0000000,0,None,4,0x200000,None)
  if lock not in (0,INVALID):break
  time.sleep(.1)
 else:raise RuntimeError('recovery_lock_failed')
 try:
  if (root/'recovery-result.json').exists():return read(root/'recovery-result.json')
  result={'schema':'g41_recovery_v1','reason':reason,'job_terminated':False,'job_active_zero':False,'firewall_restored':False,'fingerprint_match':False,'error_code':None}
  save(root/'lease.json',{'phase':'releasing'})
  if not job:job=K.OpenJobObjectW(12,False,c['job_name']);own=True
  if not job:raise RuntimeError('owned_job_missing_no_restore')
  result['active_before_termination']=n.active(job)
  n.end_job(job);result['job_terminated']=True;result['job_active_zero']=n.active(job)==0
  save(root/'component-proof.json',{'job_terminated':True,'job_active_zero':result['job_active_zero']})
  if (root/'gate-armed.json').exists():
   restored=gate(c,'Restore');result['firewall_restored']=restored['restored'];result['fingerprint_match']=restored['fingerprint_match']
  else:result['firewall_restored']=True;result['fingerprint_match']=True
  save(root/'lease.json',{'phase':'released'});save(root/'recovery-result.json',result)
  return result
 finally:
  if own and job:K.CloseHandle(job)
  if lock not in (None,0,INVALID):K.CloseHandle(lock)

def watchdog(root):
 c=context(root);root=Path(root);job=K.OpenJobObjectW(12,False,c['job_name'])
 if not job:raise RuntimeError('watchdog_job_missing')
 try:
  peer.verify_controller(c['controller'])
  save(root/'watchdog-ready.json',{'ready':True,'job_handle_held':True})
  deadline=time.monotonic()+150;reason='deadline'
  while time.monotonic()<deadline:
   if (root/'release-request.json').exists():reason=read(root/'release-request.json').get('reason','fallback');break
   try:peer.verify_controller(c['controller'])
   except ValueError:reason='controller_exit';break
   time.sleep(.1)
  if reason not in {'finish','cancel','controller_exit','deadline','fallback'}:reason='fallback'
  recover(c,reason,job)
 finally:K.CloseHandle(job)
if __name__=='__main__':
 try:
  if sys.argv[1]=='watchdog':watchdog(sys.argv[2])
  else:recover(context(sys.argv[2]),'fallback')
 except Exception:
  # Preserve fixed failure evidence; never print policy paths or request values.
  try:save(Path(sys.argv[2])/'recovery-failed.json',{'failed':True,'error_code':'scoped_recovery_failed'})
  except Exception:pass
  raise SystemExit(2)
