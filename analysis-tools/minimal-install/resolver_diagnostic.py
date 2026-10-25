"""Bounded resolver diagnosis; no installer download, launch, firewall or TLS changes."""
import ipaddress,json,os,re,socket,stat,subprocess,sys,tempfile
from pathlib import Path
BRANCH='research/battlenet-minimal-install-isolation-2026-10-25'
APPROVAL='lab: approved DNS resolver diagnosis D1 20261025'
DOMAINS=('telemetry-in.battle.net','level3.blizzard.com','us.version.battle.net')
FAMILIES={'any':socket.AF_UNSPEC,'ipv4':socket.AF_INET,'ipv6':socket.AF_INET6}
STATUSES={'answers','dns_error','os_error','timeout','helper_nonzero','output_rejected','helper_start_failed'}
CATEGORIES={'unspecified','loopback','public','other_nonpublic','invalid'}
STAGES=('before','override','restored')

def authorized(env,platform):
 return (platform=='win32' and env.get('GITHUB_ACTIONS')=='true' and env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('RUNNER_OS')=='Windows' and env.get('GITHUB_REF')=='refs/heads/'+BRANCH and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('BNET_DNS_DIAG')==APPROVAL and bool(re.fullmatch('[a-f0-9]{40}',env.get('GITHUB_SHA',''))) and bool(re.fullmatch('[0-9]{1,30}',env.get('GITHUB_RUN_ID',''))))

def classify(values):
 counts={k:0 for k in sorted(CATEGORIES)}
 for text in set(values):
  try:
   address=ipaddress.ip_address(text);address=getattr(address,'ipv4_mapped',None) or address
   category='unspecified' if address.is_unspecified else 'loopback' if address.is_loopback else 'public' if address.is_global else 'other_nonpublic'
  except (ValueError,TypeError):category='invalid'
  counts[category]+=1
 return counts

def result(status,code=None,counts=None):
 return dict(status=status,error_code=code,answer_classes=counts or {k:0 for k in sorted(CATEGORIES)})

def child(domain,family):
 if domain not in DOMAINS+('0.0.0.0',) or family not in FAMILIES:raise ValueError('probe_input')
 try:return result('answers',counts=classify(x[4][0] for x in socket.getaddrinfo(domain,443,family=FAMILIES[family],type=socket.SOCK_STREAM)))
 except socket.gaierror as exc:return result('dns_error',exc.errno if type(exc.errno) is int else None)
 except OSError as exc:return result('os_error',exc.errno if type(exc.errno) is int else None)

def validate_probe(p):
 if type(p) is not dict or set(p)!={'status','error_code','answer_classes'} or p['status'] not in STATUSES:raise ValueError('probe_schema')
 if p['error_code'] is not None and (type(p['error_code']) is not int or not -2**31<=p['error_code']<2**31):raise ValueError('probe_code')
 c=p['answer_classes']
 if type(c) is not dict or set(c)!=CATEGORIES or any(type(n) is not int or not 0<=n<=256 for n in c.values()):raise ValueError('probe_classes')
 if sum(c.values())>256 or (p['status']!='answers' and sum(c.values())!=0):raise ValueError('probe_crossfoot')
 return p

def probe(domain,family,env,run=subprocess.run):
 code='import sys;sys.path.insert(0,sys.argv.pop(1));import json;from resolver_diagnostic import child;print(json.dumps(child(sys.argv[1],sys.argv[2])))'
 try:
  p=run([sys.executable,'-I','-c',code,str(Path(__file__).resolve().parent),domain,family],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,check=False)
  if p.returncode:return result('helper_nonzero',p.returncode if -2**31<=p.returncode<2**31 else None)
  if len(p.stdout)>4096:return result('output_rejected')
  try:return validate_probe(json.loads(p.stdout))
  except (ValueError,TypeError,UnicodeError):return result('output_rejected')
 except subprocess.TimeoutExpired:return result('timeout')
 except OSError:return result('helper_start_failed')

def safe_path(path):
 try:return all(not stat.S_ISLNK(p.lstat().st_mode) and not (getattr(p.lstat(),'st_file_attributes',0)&1024) for p in [path,*path.parents])
 except OSError:return False

def validate_report(r):
 if type(r) is not dict or set(r)!={'schema','source_commit','run_id','status','installer_launched','raw_answers_exported','numeric_self_test','cases','error_code'}:raise ValueError('report_schema')
 if r['schema']!='bnet-dns-diagnostic-d1' or not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('report_identity')
 if r['installer_launched'] is not False or r['raw_answers_exported'] is not False or r['status'] not in ('complete','stopped'):raise ValueError('report_scope')
 if r['error_code'] not in (None,'diagnostic_failed','unsafe_hosts_path','hosts_format_refused','hosts_write_failed','hosts_restore_failed','dns_flush_failed'):raise ValueError('report_error')
 if r['numeric_self_test'] is not None:validate_probe(r['numeric_self_test'])
 if type(r['cases']) is not list or len(r['cases'])>3:raise ValueError('case_count')
 for index,c in enumerate(r['cases']):
  if type(c) is not dict or set(c)!={'domain','backup_created','override_written','restored','flush_exit_code','restore_flush_exit_code','stages'} or c['domain']!=DOMAINS[index]:raise ValueError('case_schema')
  for k in ('backup_created','override_written','restored'):
   if type(c[k]) is not bool:raise ValueError('case_boolean')
  for k in ('flush_exit_code','restore_flush_exit_code'):
   if c[k] is not None and (type(c[k]) is not int or not -2**31<=c[k]<2**31):raise ValueError('flush_code')
  if type(c['stages']) is not dict or not set(c['stages'])<=set(STAGES):raise ValueError('stages')
  for stage,s in c['stages'].items():
   if type(s) is not dict or set(s)!={'legacy_verified','families'} or type(s['legacy_verified']) is not bool or type(s['families']) is not dict or set(s['families'])!=set(FAMILIES):raise ValueError('stage_schema')
   for p in s['families'].values():validate_probe(p)
  if c['restored'] and (not c['backup_created'] or c['restore_flush_exit_code']!=0):raise ValueError('restore_crossfoot')
 if r['status']=='complete' and (len(r['cases'])!=3 or any(not c['restored'] or not c['override_written'] or c['flush_exit_code']!=0 or set(c['stages'])!=set(STAGES) for c in r['cases'])):raise ValueError('complete_crossfoot')
 return r

def main():
 if not authorized(os.environ,sys.platform):raise SystemExit('approved_disposable_dns_diagnostic_required')
 # Identical child environment sanitization to the installer experiment.
 base=Path(__file__).resolve().parents[2];sys.path.insert(0,str(base/'scripts'))
 import observe_agent as obs
 from hosts_experiment import flush,resolve_override
 env=obs.clean_environment(os.environ)
 report=dict(schema='bnet-dns-diagnostic-d1',source_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],status='stopped',installer_launched=False,raw_answers_exported=False,numeric_self_test=None,cases=[],error_code=None)
 def write():
  validate_report(report);out=Path('output/dns-diagnostic-d1.json');out.parent.mkdir(exist_ok=True)
  out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 def observe(domain):
  return dict(legacy_verified=resolve_override(domain,env),families={family:probe(domain,family,env) for family in FAMILIES})
 try:
  report['numeric_self_test']=probe('0.0.0.0','any',env)
  path=Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts'
  if not safe_path(path):raise ValueError('unsafe_hosts_path')
  with tempfile.TemporaryDirectory(prefix='bnet-dns-d1-',dir=os.environ['RUNNER_TEMP']) as tmp:
   for index,domain in enumerate(DOMAINS):
    if not safe_path(path):raise ValueError('unsafe_hosts_path')
    original=path.read_bytes()
    if len(original)>262144 or b'\x00' in original:raise ValueError('hosts_format_refused')
    c=dict(domain=domain,backup_created=False,override_written=False,restored=False,flush_exit_code=None,restore_flush_exit_code=None,stages={});report['cases'].append(c)
    with (Path(tmp)/f'{index}.bak').open('xb') as f:f.write(original)
    c['backup_created']=True;c['stages']['before']=observe(domain);write()
    updated=original+b'\r\n# BEGIN BNET DNS D1\r\n'+('0.0.0.0 '+domain+'\r\n:: '+domain+'\r\n').encode('ascii')+b'# END BNET DNS D1\r\n'
    touched=False
    try:
     touched=True;path.write_bytes(updated)
     if path.read_bytes()!=updated:raise ValueError('hosts_write_failed')
     c['override_written']=True;c['flush_exit_code']=flush(env)
     if c['flush_exit_code']!=0:raise ValueError('dns_flush_failed')
     c['stages']['override']=observe(domain);write()
    finally:
     if touched:
      if not safe_path(path) or path.read_bytes()!=updated:raise ValueError('hosts_restore_failed')
      path.write_bytes(original)
      if path.read_bytes()!=original:raise ValueError('hosts_restore_failed')
      c['restore_flush_exit_code']=flush(env);c['restored']=c['restore_flush_exit_code']==0;write()
      if not c['restored']:raise ValueError('hosts_restore_failed')
    c['stages']['restored']=observe(domain);write()
  report['status']='complete'
 except Exception as exc:
  report['error_code']=str(exc) if type(exc) is ValueError and str(exc) in {'unsafe_hosts_path','hosts_format_refused','hosts_write_failed','hosts_restore_failed','dns_flush_failed'} else 'diagnostic_failed'
 finally:write()
 print(json.dumps({'status':report['status'],'cases_recorded':len(report['cases']),'installer_launched':False}))

if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--validate':
  validate_report(json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')))
 else:main()
