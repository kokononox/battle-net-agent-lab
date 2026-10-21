import base64,ctypes,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from backend import BASE,Manager,digest

def verify_package():
 for name,expected in json.loads((BASE/'MANIFEST-SHA256.json').read_text('utf-8')).items():
  path=Path(name)
  if path.is_absolute() or '..' in path.parts or digest(BASE/path)!=expected:raise RuntimeError('package_integrity_failed')
def message(text):ctypes.windll.user32.MessageBoxW(None,text,'WoW Blacklist',0x10)
def run():
 if os.name!='nt' or ctypes.sizeof(ctypes.c_void_p)!=8:raise RuntimeError('Windows x64 required')
 verify_package()
 if not ctypes.windll.shell32.IsUserAnAdmin():
  args=subprocess.list2cmdline(['-I',str(BASE/'app/main.py'),*sys.argv[1:]])
  shell=ctypes.windll.shell32.ShellExecuteW;shell.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_int];shell.restype=ctypes.c_void_p
  code=shell(None,'runas',str(BASE/'runtime/pythonw.exe'),args,str(BASE),1)
  if not code or int(code)<=32:raise RuntimeError('Administrator approval cancelled; no action performed')
  return
 kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p];kernel.CreateMutexW.restype=ctypes.c_void_p;kernel.CloseHandle.argtypes=[ctypes.c_void_p]
 handle=kernel.CreateMutexW(None,False,'Local\\WoWBlacklistManagerUiV1')
 if not handle or ctypes.get_last_error()==183:raise RuntimeError('Another blacklist window is open; close it first')
 try:
  if '--restore' in sys.argv:
   Manager().run('restore');ctypes.windll.user32.MessageBoxW(None,'Verified: no rules owned by this blacklist installation remain. Other firewall rules were not changed.','WoW Blacklist',0x40);return
  env=os.environ.copy();env['WOW_BL_ROOT']=str(BASE)
  code="& ([scriptblock]::Create([IO.File]::ReadAllText('"+str(BASE/'app/ui.ps1').replace("'","''")+"')))"
  ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
  p=subprocess.run([str(ps),'-NoLogo','-NoProfile','-STA','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],env=env,capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  if p.returncode:raise RuntimeError('Window failed. Existing blacklist rules may remain. Use Restore.cmd from the same folder.')
 finally:kernel.CloseHandle(handle)
if __name__=='__main__':
 try:run()
 except Exception as e:
  if os.name=='nt':message(str(e)[:250])
  else:raise
