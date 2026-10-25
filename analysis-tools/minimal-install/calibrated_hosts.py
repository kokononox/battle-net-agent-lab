"""Calibrated OS-resolver-only hosts gate. Never proves all network paths blocked.
Only accepts target no-data (11004) with positive baseline + independent healthy
control + exact file readback. All other DNS errors, helper failures and timeouts
remain failures. The original C1 gate and historical results are not rewritten.
"""
import json,os,socket,subprocess,sys
from pathlib import Path
from resolver_diagnostic import DOMAINS,FAMILIES,classify,result,validate_probe,safe_path
from hosts_experiment import flush
CONTROL='downloader.battle.net'
POLICY='calibrated_os_resolver_v2'

def child(domain,family):
 if domain not in (*DOMAINS,CONTROL,'0.0.0.0') or family not in FAMILIES:raise ValueError('unapproved_probe')
 try:return result('answers',counts=classify(x[4][0] for x in socket.getaddrinfo(domain,443,family=FAMILIES[family],type=socket.SOCK_STREAM)))
 except socket.gaierror as exc:return result('dns_error',exc.errno if type(exc.errno) is int else None)
 except OSError as exc:return result('os_error',exc.errno if type(exc.errno) is int else None)

def probe(domain,family,env,run=subprocess.run):
 if domain not in (*DOMAINS,CONTROL,'0.0.0.0') or family not in FAMILIES:raise ValueError('unapproved_probe')
 code='import sys;sys.path.insert(0,sys.argv.pop(1));import json;from calibrated_hosts import child;print(json.dumps(child(sys.argv[1],sys.argv[2])))'
 try:
  p=run([sys.executable,'-I','-c',code,str(Path(__file__).resolve().parent),domain,family],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,check=False)
  if p.returncode:return result('helper_nonzero',p.returncode if -2**31<=p.returncode<2**31 else None)
  if len(p.stdout)>4096:return result('output_rejected')
  try:return validate_probe(json.loads(p.stdout))
  except (ValueError,TypeError,UnicodeError):return result('output_rejected')
 except subprocess.TimeoutExpired:return result('timeout')
 except OSError:return result('helper_start_failed')

def family_view(domain,env):return {family:probe(domain,family,env) for family in FAMILIES}

def only(p,category):
 try:
  validate_probe(p);c=p['answer_classes']
  return p['status']=='answers' and c[category]>0 and sum(c.values())==c[category]
 except (ValueError,TypeError,KeyError):return False

def healthy(view):
 # IPv6 absence at baseline is not evidence of blocking. Require a positive
 # ordinary resolution and a positive IPv4 resolution, both public only.
 return all(only(view.get(family,{}),'public') for family in ('any','ipv4'))

def blocked_state(view):
 if type(view) is not dict or set(view)!=set(FAMILIES):return 'refused'
 kinds=[]
 for p in view.values():
  try:validate_probe(p)
  except (ValueError,TypeError):return 'refused'
  if only(p,'unspecified'):kinds.append('unspecified')
  elif p['status']=='dns_error' and p['error_code']==11004:kinds.append('no_data')
  else:return 'refused'
 return 'accepted_'+('mixed' if len(set(kinds))>1 else kinds[0])

def blank(domain):
 if domain not in DOMAINS:raise ValueError('unapproved_target')
 return dict(domain=domain,control_domain=CONTROL,policy=POLICY,backup_created=False,override_written=False,baseline=None,checks=[],verification_failures=0,flush_exit_code=None,restore_attempted=False,file_restored=False,restore_flush_exit_code=None,restoration=None,restored=False)

def validate_pair(pair):
 if type(pair) is not dict or set(pair)!={'target','control'}:raise ValueError('pair_schema')
 for v in pair.values():
  if type(v) is not dict or set(v)!=set(FAMILIES):raise ValueError('family_schema')
  for p in v.values():validate_probe(p)

def validate_record(r):
 if type(r) is not dict or r.get('domain') not in DOMAINS or set(r)!=set(blank(r['domain'])) or r['control_domain']!=CONTROL or r['policy']!=POLICY:raise ValueError('calibration_schema')
 for k in ('backup_created','override_written','restore_attempted','file_restored','restored'):
  if type(r[k]) is not bool:raise ValueError('calibration_bool')
 for k in ('flush_exit_code','restore_flush_exit_code'):
  if r[k] is not None and (type(r[k]) is not int or not -2**31<=r[k]<2**31):raise ValueError('calibration_flush')
 for k in ('baseline','restoration'):
  if r[k] is not None:validate_pair(r[k])
 if type(r['checks']) is not list or len(r['checks'])>64 or type(r['verification_failures']) is not int or not 0<=r['verification_failures']<=64:raise ValueError('calibration_counts')
 for c in r['checks']:
  if type(c) is not dict or set(c)!={'observations','readback_verified','resolver_state','accepted'} or type(c['accepted']) is not bool or type(c['readback_verified']) is not bool:raise ValueError('check_schema')
  validate_pair(c['observations'])
  if c['resolver_state']!=blocked_state(c['observations']['target']):raise ValueError('check_state')
  accepted=bool(r['baseline'] is not None and healthy(r['baseline']['target']) and healthy(r['baseline']['control']) and c['readback_verified'] and r['backup_created'] and r['override_written'] and r['flush_exit_code']==0 and healthy(c['observations']['control']) and c['resolver_state']!='refused')
  if c['accepted']!=accepted:raise ValueError('check_acceptance')
 if r['verification_failures']!=sum(not c['accepted'] for c in r['checks']):raise ValueError('check_failures')
 if r['file_restored'] and not r['restore_attempted']:raise ValueError('file_restore_crossfoot')
 if r['restored'] and (not r['backup_created'] or not r['file_restored'] or r['restore_flush_exit_code']!=0 or r['restoration'] is None or not healthy(r['restoration']['target']) or not healthy(r['restoration']['control'])):raise ValueError('restore_crossfoot')
 return r

class CalibratedHosts:
 def __init__(self,path,work,record,env,observe=family_view,flush_fn=flush,safe=safe_path):
  validate_record(record);self.path=Path(path);self.work=Path(work);self.r=record;self.env=env;self.observe=observe;self.flush_fn=flush_fn;self.safe=safe;self.original=None;self.updated=None;self.touched=False
 def pair(self):return dict(target=self.observe(self.r['domain'],self.env),control=self.observe(CONTROL,self.env))
 def readback(self):
  try:return self.safe(self.path) and self.path.read_bytes()==self.updated
  except OSError:return False
 def apply(self):
  r=self.r
  if not self.safe(self.path):raise ValueError('calibration_path_refused')
  original=self.path.read_bytes()
  if len(original)>262144 or b'\x00' in original:raise ValueError('calibration_hosts_format_refused')
  r['baseline']=self.pair()
  if not healthy(r['baseline']['target']) or not healthy(r['baseline']['control']):raise ValueError('calibration_baseline_not_healthy')
  # Baseline observation may take time: recheck bytes before backup/write.
  if not self.safe(self.path) or self.path.read_bytes()!=original:raise ValueError('calibration_hosts_changed_before_write')
  self.original=original
  with (self.work/'hosts-before.bak').open('xb') as f:f.write(original)
  r['backup_created']=True
  self.updated=original+b'\r\n# BEGIN BNET CALIBRATED HOSTS V2\r\n'+('0.0.0.0 '+r['domain']+'\r\n:: '+r['domain']+'\r\n').encode('ascii')+b'# END BNET CALIBRATED HOSTS V2\r\n'
  self.touched=True;self.path.write_bytes(self.updated)
  if not self.readback():raise ValueError('calibration_write_failed')
  r['override_written']=True;r['flush_exit_code']=self.flush_fn(self.env)
  if r['flush_exit_code']!=0:raise ValueError('calibration_flush_failed')
  if not self.check():raise ValueError('calibration_override_not_verified')
 def check(self):
  r=self.r
  if not self.touched or len(r['checks'])>=64:return False
  before=self.readback();observations=self.pair();readback=before and self.readback();state=blocked_state(observations['target'])
  accepted=bool(r['baseline'] is not None and healthy(r['baseline']['target']) and healthy(r['baseline']['control']) and readback and r['backup_created'] and r['override_written'] and r['flush_exit_code']==0 and healthy(observations['control']) and state!='refused')
  r['checks'].append(dict(observations=observations,readback_verified=readback,resolver_state=state,accepted=accepted))
  if not accepted:r['verification_failures']+=1
  return accepted
 def restore(self):
  r=self.r
  if not self.touched:return True
  if r['restore_attempted']:return r['restored']
  r['restore_attempted']=True
  if not self.readback():return False # Never overwrite an unrelated change.
  self.path.write_bytes(self.original)
  if not self.safe(self.path) or self.path.read_bytes()!=self.original:return False
  r['file_restored']=True;r['restore_flush_exit_code']=self.flush_fn(self.env)
  r['restoration']=self.pair()
  r['restored']=bool(r['restore_flush_exit_code']==0 and healthy(r['restoration']['target']) and healthy(r['restoration']['control']) and self.safe(self.path) and self.path.read_bytes()==self.original)
  return r['restored']
