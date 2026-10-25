"""Reversible exact-host loopback steering, never an outbound firewall substitute."""
import hashlib,os,socket,stat,subprocess,sys,json
from pathlib import Path
from domain_proxy import HOSTS

def ordinary(path):
 try:return all(not stat.S_ISLNK(p.lstat().st_mode) and not getattr(p.lstat(),'st_file_attributes',0)&1024 for p in [path,*path.parents])
 except OSError:return False

class Redirect:
 def __init__(self,work,env):
  self.work=Path(work);self.env=env;self.path=Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts';self.original=None;self.updated=None;self.touched=False;self.restored=False
 def prepare(self):
  if not ordinary(self.path):raise ValueError('hosts_path_refused')
  b=self.path.read_bytes()
  if len(b)>262144 or b'\0' in b:raise ValueError('hosts_format_refused')
  for line in b.decode('utf-8',errors='replace').splitlines():
   names=line.split('#',1)[0].split()[1:]
   if any(n.lower() in HOSTS for n in names):raise ValueError('existing_target_hosts_mapping_refused')
  self.original=b;self.updated=b+b'\r\n# BEGIN BNET TWO HOSTS LOOPBACK\r\n'+''.join('127.0.0.1 '+h+'\r\n::1 '+h+'\r\n' for h in sorted(HOSTS)).encode()+b'# END BNET TWO HOSTS LOOPBACK\r\n'
  (self.work/'hosts-before.bak').write_bytes(b);(self.work/'hosts-after.expected').write_bytes(self.updated)
 def flush(self):
  p=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/ipconfig.exe'),'/flushdns'],env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False)
  return p.returncode==0
 def apply(self):
  if not ordinary(self.path) or self.path.read_bytes()!=self.original:raise ValueError('hosts_changed_before_steering')
  self.touched=True;self.path.write_bytes(self.updated)
  if self.path.read_bytes()!=self.updated or not self.flush():raise ValueError('hosts_steering_write_or_flush_failed')
  code="import socket,json;print(json.dumps({h:sorted({x[4][0] for x in socket.getaddrinfo(h,80,type=socket.SOCK_STREAM)}) for h in ['us.version.battle.net','level3.blizzard.com']}))"
  p=subprocess.run([sys.executable,'-I','-c',code],env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)
  if p.returncode or len(p.stdout)>4096:raise ValueError('hosts_steering_probe_failed')
  v=json.loads(p.stdout)
  if set(v)!=HOSTS or any(not addresses or not set(addresses)<={'127.0.0.1','::1'} for addresses in v.values()):raise ValueError('hosts_steering_not_loopback_only')
  if self.path.read_bytes()!=self.updated:raise ValueError('hosts_steering_changed')
  return True
 def restore(self):
  if not self.touched:return True
  if not ordinary(self.path):return False
  current=self.path.read_bytes()
  if current not in (self.updated,self.original):return False
  if current!=self.original:self.path.write_bytes(self.original)
  self.restored=self.path.read_bytes()==self.original and self.flush()
  return self.restored
