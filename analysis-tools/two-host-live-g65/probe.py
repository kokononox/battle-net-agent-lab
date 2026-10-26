"""Read-only Win32 GUI/process probe. Never exports raw UI text or touches controls."""
import ctypes as C,re,json,os,subprocess
from pathlib import Path
from ctypes import wintypes as W
LABELS={'ok','continue','cancel','install','next','back','close','language','select a language','english (us)','english','battle.net setup','setup','updating battle.net','installing battle.net'}
MARKERS=('language','error','install','update','login','network','initializing','connecting','download','failed')
def inspect(pids):
 U=C.WinDLL('user32',use_last_error=True);K=C.WinDLL('kernel32',use_last_error=True)
 CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
 U.EnumWindows.argtypes=[CB,W.LPARAM];U.EnumChildWindows.argtypes=[W.HWND,CB,W.LPARAM]
 U.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
 U.IsWindowVisible.argtypes=[W.HWND];U.IsWindowVisible.restype=W.BOOL
 U.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
 U.SendMessageTimeoutW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM,W.UINT,W.UINT,C.POINTER(C.c_size_t)]
 U.SendMessageTimeoutW.restype=W.LPARAM
 K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=W.HANDLE
 K.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)];K.CloseHandle.argtypes=[W.HANDLE]
 rows=[];errors=0;seen=0
 def collect(hwnd):
  nonlocal errors,seen
  pid=W.DWORD();U.GetWindowThreadProcessId(hwnd,C.byref(pid))
  if pid.value not in pids or not U.IsWindowVisible(hwnd):return
  seen+=1
  cls=C.create_unicode_buffer(128);U.GetClassNameW(hwnd,cls,128);kind=cls.value.lower()
  # Only known non-edit native controls, never Chromium/edit/password/unknown.
  if kind not in {'#32770','button','static','combobox'}:return
  if len(rows)>=64:return
  b=C.create_unicode_buffer(513);n=C.c_size_t()
  if not U.SendMessageTimeoutW(hwnd,0x000D,513,C.addressof(b),3,100,C.byref(n)):errors+=1;return
  text=' '.join(b.value.replace('&','').lower().split())
  rows.append({'class':kind,'label':text if text in LABELS else 'unrecognized','markers':[x for x in MARKERS if re.search(r'\b'+x+r'\b',text)]})
 @CB
 def child(hwnd,param):
  try:collect(hwnd)
  except Exception:pass
  return len(rows)<64
 @CB
 def top(hwnd,param):
  pid=W.DWORD();U.GetWindowThreadProcessId(hwnd,C.byref(pid))
  if pid.value in pids:
   collect(hwnd);U.EnumChildWindows(hwnd,child,0)
  return len(rows)<64
 U.EnumWindows(top,0);states=[]
 for pid in sorted(pids)[:24]:
  h=K.OpenProcess(0x1000,False,pid)
  if not h:states.append('unavailable_or_exited');continue
  try:
   n=W.DWORD();states.append('running' if K.GetExitCodeProcess(h,C.byref(n)) and n.value==259 else 'exited_or_query_failed')
  finally:K.CloseHandle(h)
 uia={'status':'not_started'}
 try:
  exe=Path(os.environ['RUNNER_TEMP'])/'g65-read-ui.exe'
  result=subprocess.run([str(exe),*[str(p) for p in sorted(pids)[:24]]],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=6)
  if result.returncode!=0 or len(result.stdout)>65536:uia={'status':'helper_failed'}
  else:
   uia=json.loads(result.stdout.decode('utf-8-sig'))
   if uia.get('actions_performed') is not False or uia.get('raw_text_exported') is not False:raise ValueError('unsafe_UI_output')
 except subprocess.TimeoutExpired:uia={'status':'timeout'}
 except Exception:uia={'status':'probe_failed'}
 return {'UIA':uia,'process_states':states,'visible_owned_controls_seen':seen,'recognized_control_rows':rows,'read_errors':errors,'raw_text_exported':False,'actions_performed':False,'coverage_complete':False}
