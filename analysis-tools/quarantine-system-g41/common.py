import json,os,re,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
class Stopped(RuntimeError):pass

def save(path,value):
 path=Path(path);temp=path.with_name(path.name+'.tmp');temp.write_text(json.dumps(value,separators=(',',':')));os.replace(temp,path)
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def context(root):
 root=Path(root).absolute();base=Path(os.environ['ProgramData'])/'BNetOnlineG41'
 if root.parent!=base or re.fullmatch('[a-f0-9]{32}',root.name) is None:raise Stopped('context_scope')
 c=read(root/'config.json')
 if c['root']!=str(root) or c['job_name']!='Global\\BNetOnlineG41_'+root.name:raise Stopped('context_identity')
 return c

def wait_file(path,seconds=20):
 end=time.monotonic()+seconds
 while not Path(path).exists() and time.monotonic()<end:
  if Path(path).name=='recovery-result.json' and Path(path).with_name('recovery-failed.json').exists():raise Stopped('scoped_recovery_failed')
  time.sleep(.05)
 if not Path(path).exists():raise Stopped('receipt_timeout')
 return read(path)
def gate(c,action):
 ps=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
 p=subprocess.run([ps,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(ROOT/'Gate.ps1'),'-Action',action,'-Config',str(Path(c['root'])/'config.json')],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60)
 try:v=json.loads(p.stdout.decode('utf-8-sig'))
 except ValueError:raise Stopped('gate_output_invalid') from None
 if p.returncode or v.get('error_code'):raise Stopped(v.get('error_code','gate_failed'))
 return v
