"""Read-only UI samples for live members of the exact Job; no interaction or account input."""
import ctypes as C,json,os,sys,time
from ctypes import wintypes as W
from pathlib import Path
root=Path(sys.argv[1]);base=Path(__file__).resolve().parents[2];sys.path.insert(0,str(base/'scripts'));import ui_accessibility as uia
uia._HELPER=(root/'NativeUI.exe',None)
c=json.loads((root/'config.json').read_text(encoding='utf-8-sig'))
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
k.OpenJobObjectW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR];k.OpenJobObjectW.restype=W.HANDLE
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,C.POINTER(W.BOOL)];k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)];k.CloseHandle.argtypes=[W.HANDLE]
u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];u.IsWindowVisible.argtypes=[W.HWND]
CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM);u.EnumWindows.argtypes=[CB,W.LPARAM]
r={'schema':'live_job_readonly_ui_v1','actions_performed':False,'login_attempted':False,'samples':[],'query_errors':0,'job_opened':False};start=time.monotonic();job=k.OpenJobObjectW(4,False,c['job_name'])
def save():(root/'completion-ui.json').write_text(json.dumps(r))
try:
 if not job:raise ValueError('job_not_open')
 r['job_opened']=True
 while time.monotonic()-start<255:
  targets=[];categories={}
  @CB
  def collect(hwnd,_):
   if not u.IsWindowVisible(hwnd) or len(targets)>=8:return True
   pid=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(pid));h=k.OpenProcess(0x1000,False,pid.value)
   if not h:return True
   try:
    member=W.BOOL()
    if not k.IsProcessInJob(h,job,C.byref(member)) or not member.value:return True
    buf=C.create_unicode_buffer(32768);size=W.DWORD(32768)
    if not k.QueryFullProcessImageNameW(h,0,buf,C.byref(size)):return True
    image=Path(buf.value);name=image.name.lower();category=None
    pf=(Path(os.environ['ProgramFiles(x86)'])/'Battle.net').resolve();pd=(Path(os.environ['ProgramData'])/'Battle.net').resolve()
    if name=='battle.net-setup.exe' and image.resolve()==(root/'Battle.net-Setup.exe').resolve():category='setup'
    elif name in {'battle.net.exe','battle.net launcher.exe'} and image.resolve().is_relative_to(pf):category='client'
    elif name=='agent.exe' and image.resolve().is_relative_to(pd):category='agent'
    if category:targets.append({'hwnd':int(hwnd),'pid':pid.value});categories[pid.value]=category
   finally:k.CloseHandle(h)
   return True
  u.EnumWindows(collect,0);sample=uia.inspect(targets);elements=sample['elements']
  client_elements=[e for e in elements if categories.get(e['pid'])=='client']
  login_marker=any(m in {'login','sign_in','login_page'} for e in client_elements for m in e['markers'])
  login_controls=login_marker and any(e['password'] for e in client_elements) and any(e['control_type']=='Button' for e in client_elements)
  r['samples'].append({'client_login_marker_present':login_marker,'client_login_controls_present':login_controls,'elapsed_seconds':int(time.monotonic()-start),'status':sample['status'],'window_kinds':sorted(set(categories.values())),'client_window_present':'client' in categories.values(),'labels':sorted({e['label'] for e in elements if e['label'] not in {'not_read','unrecognized'}}),'markers':sorted({m for e in elements for m in e['markers']}),'control_types':sorted({e['control_type'] for e in elements}),'truncated':sample['truncated']})
  if len(r['samples'])>=44:break
  save();time.sleep(6)
except Exception:r['query_errors']+=1
finally:
 if job:k.CloseHandle(job)
 save()
