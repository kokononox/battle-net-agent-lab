"""Windows launcher. Verifies package files then opens read-only/development UI."""
from pathlib import Path
import ctypes,hashlib,json,os,subprocess
BASE=Path(__file__).resolve().parents[1]
def run():
    if os.name!='nt':raise RuntimeError('Windows x64 is required for the desktop interface.')
    manifest=json.loads((BASE/'MANIFEST-SHA256.json').read_text('utf-8'))
    for name,expected in manifest.items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Invalid package manifest.')
        p=BASE/relative
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise RuntimeError('Package integrity check failed: '+name)
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    # RemoteSigned applies to this child process only; managed policy still prevails.
    result=subprocess.run([str(ps),'-NoLogo','-NoProfile','-STA','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/ui.ps1')],capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        detail=result.stderr.decode('utf-8',errors='replace')[:1000]
        raise RuntimeError('The development UI did not start. No firewall changes were requested. Do not lower Windows security settings.\n'+detail)
if __name__=='__main__':
    try:run()
    except Exception as e:
        if os.name=='nt':ctypes.windll.user32.MessageBoxW(None,str(e),'Unified Firewall DEV',0x10)
        else:raise
