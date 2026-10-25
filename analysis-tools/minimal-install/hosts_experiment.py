"""Reversible exact-domain hosts override on approved disposable Windows only.
Tests the OS resolver path, NOT all traffic, private DNS or server receipt.
"""
import ipaddress,os,socket,subprocess,sys
from pathlib import Path
from experiment_policy import DOMAINS,hosts_blank

def null_answers(values):
 try:
  answers=[ipaddress.ip_address(x) for x in values]
  return bool(answers) and all(a.is_unspecified or (getattr(a,'ipv4_mapped',None) is not None and a.ipv4_mapped.is_unspecified) for a in answers)
 except (ValueError,TypeError):return False

def flush(env):
 try:return subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'ipconfig.exe'),'/flushdns'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False).returncode
 except (OSError,subprocess.TimeoutExpired):return -1

def resolve_override(domain,env):
 # Fresh child queries Windows resolver; no DNS answer text leaves this process.
 code="import socket,sys;from hosts_experiment import null_answers;sys.exit(0 if null_answers({x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)}) else 1)"
 try:
  proc=subprocess.run([sys.executable,'-I','-c',"import sys;sys.path.insert(0,sys.argv.pop(1));"+code,str(Path(__file__).resolve().parent),domain],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=False)
  return proc.returncode==0
 except (OSError,subprocess.TimeoutExpired):return False

class HostsExperiment:
 def __init__(self,path,work,record,env,flush_fn=flush,resolve_fn=resolve_override,safe_path=lambda p:True):
  if record['domain'] is not None and record['domain'] not in DOMAINS:raise ValueError('hosts_domain_not_approved')
  self.path=Path(path);self.work=Path(work);self.record=record;self.env=env;self.flush_fn=flush_fn;self.resolve_fn=resolve_fn;self.safe_path=safe_path;self.original=None;self.updated=None;self.touched=False
 def apply(self):
  r=self.record;domain=r['domain']
  if domain is None:return
  if not self.safe_path(self.path):raise ValueError('hosts_path_refused')
  original=self.path.read_bytes()
  if len(original)>262144 or b'\x00' in original:raise ValueError('hosts_original_format_refused')
  self.original=original
  with (self.work/'hosts-before.bak').open('xb') as backup:backup.write(original)
  r['backup_created']=True
  self.updated=original+b'\r\n# BEGIN BNET MINIMAL C1\r\n'+('0.0.0.0 '+domain+'\r\n:: '+domain+'\r\n').encode('ascii')+b'# END BNET MINIMAL C1\r\n'
  self.touched=True;self.path.write_bytes(self.updated)
  if self.path.read_bytes()!=self.updated:raise ValueError('hosts_write_readback_failed')
  r['override_written']=True;r['flush_exit_code']=self.flush_fn(self.env)
  if r['flush_exit_code']!=0:raise ValueError('hosts_dns_flush_failed')
  if not self.check():raise ValueError('hosts_override_verification_failed')
 def check(self):
  r=self.record
  if r['domain'] is None:return True
  r['verification_checks']+=1
  try:ok=self.safe_path(self.path) and self.path.read_bytes()==self.updated and self.resolve_fn(r['domain'],self.env)
  except OSError:ok=False
  r['resolver_verified']=bool(ok)
  if not ok:r['verification_failures']+=1
  return bool(ok)
 def restore(self):
  r=self.record
  if not self.touched:return True
  r['restore_attempted']=True
  try:
   if not self.safe_path(self.path):return False
   # Do not overwrite unrelated changes, even on a disposable runner.
   if self.path.read_bytes()!=self.updated:return False
   self.path.write_bytes(self.original)
   if self.path.read_bytes()!=self.original:return False
   r['restore_flush_exit_code']=self.flush_fn(self.env);r['restored']=r['restore_flush_exit_code']==0
   return r['restored']
  except OSError:return False

def for_runner(work,record,env,obs):
 from model import authorized
 if not authorized(os.environ,sys.platform):raise ValueError('hosts_approved_hosted_case_required')
 root=Path(os.environ['SystemRoot']);path=root/'System32'/'drivers'/'etc'/'hosts'
 def ordinary(candidate):return not any(obs.is_reparse(p) for p in (root,root/'System32',root/'System32'/'drivers',path.parent,candidate))
 return HostsExperiment(path,work,record,env,safe_path=ordinary)
