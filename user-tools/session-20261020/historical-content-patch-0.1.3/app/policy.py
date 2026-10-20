import os,json,hashlib,ipaddress,subprocess,re,base64
from pathlib import Path
from safepaths import safe_path

def digest(b):return hashlib.sha256(b).hexdigest()
def read_json(p,limit=1048576):
 p=safe_path(p)
 if not p.is_file() or p.stat().st_size>limit:raise ValueError('state_missing_or_large')
 b=p.read_bytes();return json.loads(b.decode('utf-8-sig')),digest(b)
def intervals(values):
 out=[]
 for value in values:
  if '-' in value:
   a,b=map(ipaddress.ip_address,value.split('-',1))
   if a.version!=b.version or int(a)>int(b):raise ValueError('address_range_invalid')
  else:
   net=ipaddress.ip_network(value,strict=False);a,b=net.network_address,net.broadcast_address
  out.append((a.version,int(a),int(b)))
 result=[]
 for version,a,b in sorted(out):
  if result and result[-1][0]==version and a<=result[-1][2]+1:result[-1]=(version,result[-1][1],max(b,result[-1][2]))
  else:result.append((version,a,b))
 return result

def complement(ips,version):
 current=0;result=[]
 for n in sorted(int(ipaddress.ip_address(x)) for x in ips if ipaddress.ip_address(x).version==version):
  if current<n:result.append((version,current,n-1))
  current=n+1
 last=2**(32 if version==4 else 128)-1
 if current<=last:result.append((version,current,last))
 return result

def state(root=None):
 root=Path(root) if root else Path(os.environ['ProgramData'])/'SstpWhitelistManager1'
 config,ch=read_json(root/'allowlist.json',65536)
 if config.get('schema')!='sstp-allowlist-config-1' or config.get('domains')!=['level3.blizzard.com']:raise ValueError('configuration_not_level3_only')
 manual=config.get('ip_addresses')
 if not isinstance(manual,list) or len(manual)>64 or any(not isinstance(x,str) for x in manual):raise ValueError('manual_ip_configuration_invalid')
 try:normalized=[str(ipaddress.ip_address(x)) for x in manual]
 except ValueError:raise ValueError('manual_ip_configuration_invalid')
 if normalized!=manual or len(set(manual))!=len(manual) or any(not ipaddress.ip_address(x).is_global for x in manual):raise ValueError('manual_ip_configuration_invalid')
 hashes={'config':ch};active=[];slots=[]
 for slot in ('slot-a','slot-b'):
  p=root/slot/'journal.json'
  if not p.exists():continue
  env,h=read_json(p);hashes[slot]=h
  if env.get('schema')!='sstp-journal-envelope-1' or not isinstance(env.get('payload'),str) or digest(env['payload'].encode())!=env.get('sha256'):raise ValueError('journal_integrity_failed')
  journal=json.loads(env['payload']);s=journal.get('state',{})
  if journal.get('schema')!='sstp-journal-1' or s.get('schema')!='sstp-whitelist-app-overlay-1' or s.get('pending') is not None:raise ValueError('journal_unsettled')
  phase=s.get('phase');slots.append({'slot':slot,'phase':phase})
  if phase=='active':active.append(s)
  elif phase not in {'inactive','removed'}:raise ValueError('overlay_not_settled')
 if len(active)!=1:raise ValueError('one_active_overlay_required')
 s=active[0];ips=s.get('allowed_ips',[])
 canonical={'schema':'sstp-allowlist-config-1','domains':config['domains'],'ip_addresses':manual}
 if s.get('config_sha256')!=digest(json.dumps(canonical,separators=(',',':')).encode()):raise ValueError('journal_configuration_hash_mismatch')
 if s.get('scope')!='RemoteAccess' or not isinstance(ips,list) or not 1<=len(ips)<=64:raise ValueError('overlay_scope_invalid')
 ips=[str(ipaddress.ip_address(x)) for x in ips]
 if len(set(ips))!=len(ips) or any(not ipaddress.ip_address(x).is_global for x in ips):raise ValueError('allowed_addresses_invalid')
 if not set(manual)<=set(ips):raise ValueError('manual_ips_not_in_active_snapshot')
 session=s.get('session','')
 if not re.fullmatch('[a-f0-9]{32}',session):raise ValueError('session_invalid')
 objects=s.get('objects',[])
 if len(objects)!=3:raise ValueError('objects_invalid')
 names=[]
 for o,kind in zip(objects,('guard','v4','v6')):
  name=f'SstpWhitelistApp-{session}-{kind}';spec=o.get('spec',{})
  if spec.get('name')!=name or spec.get('kind')!=kind or o.get('exists') is not True or o.get('enabled')!=(kind!='guard'):raise ValueError('overlay_objects_unsettled')
  names.append(name)
 return {'config_domains':config['domains'],'configured_manual_ips':manual,'manual_ip_domain_ownership_verified':False,'active_allowed_ips':ips,'active_ips_not_in_manual_config':[x for x in ips if x not in manual],'slot_phases':slots,'source_hashes':hashes,'names':names,'ip_origin_note':'journal_snapshot_not_fresh_dns_or_hostname_ownership_proof','outside_vpn_certified':False}

class PolicyReadError(ValueError):
 def __init__(self,code,diagnostic):
  super().__init__(code);self.diagnostic=diagnostic

def encoded_names(names):
 return base64.b64encode(json.dumps(names,separators=(',',':')).encode('utf-8')).decode('ascii')

def parse_policy_output(r):
 if len(r.stdout)>524288:raise PolicyReadError('effective_policy_output_too_large',{'stage':'transport','raw_output_exported':False})
 try:d=json.loads(r.stdout.decode('utf-8-sig'))
 except (ValueError,UnicodeError):raise PolicyReadError('effective_policy_output_unreadable',{'stage':'transport','exit_code':r.returncode,'stderr_present':bool(r.stderr),'raw_output_exported':False})
 if r.returncode or d.get('ok') is False:
  raw=d.get('error',{});safe={}
  for k in ('code','stage','rule_kind','store','exception_type','category'):
   v=raw.get(k)
   if v is None or isinstance(v,str) and re.fullmatch('[A-Za-z0-9_.+]{1,180}',v):safe[k]=v
  if type(raw.get('hresult'))is int:safe['hresult']=raw['hresult']
  safe['exit_code']=r.returncode;safe['raw_output_exported']=False
  raise PolicyReadError('effective_policy_read_failed',safe)
 return d

def policy_snapshot(s):
 exe=safe_path(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
 script=safe_path(Path(__file__).with_name('policy_read.ps1'))
 try:
  r=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),'-NamesBase64',encoded_names(s['names'])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,creationflags=0x08000000)
 except subprocess.TimeoutExpired:raise PolicyReadError('effective_policy_read_timeout',{'stage':'powershell_process','raw_output_exported':False})
 d=parse_policy_output(r);rows=d['rules']
 if d.get('identity',{}).get('passed') is not True or not re.fullmatch('[a-f0-9]{64}',d.get('session_fingerprint') or ''):raise ValueError('connected_sstp_identity_not_confirmed')
 if len(rows)!=6:raise ValueError('effective_rule_count')
 for row in rows:
  if row['name'] not in s['names'] or row['store'] not in {'PersistentStore','ActiveStore'}:raise ValueError('unexpected_policy_row')
  kind=row['name'].rsplit('-',1)[1]
  expected={'enabled':'False' if kind=='guard' else 'True','direction':'Outbound','action':'Block','profile':'Any','source_type':'Local','interface_type':'RemoteAccess','program':'Any','service':'Any'}
  if any(row.get(k)!=v for k,v in expected.items()):raise ValueError('effective_rule_semantic_mismatch')
  if row['protocol'] not in {'Any','256'} or any(row[k]!=['Any'] for k in ('local','local_port','remote_port','alias')):raise ValueError('effective_filter_semantic_mismatch')
  if kind=='guard':
   if row['remote']!=['Any']:raise ValueError('guard_address_mismatch')
  elif intervals(row['remote'])!=complement(s['active_allowed_ips'],4 if kind=='v4' else 6):raise ValueError('effective_address_complement_mismatch')
 if len({(r['name'],r['store']) for r in rows})!=6:raise ValueError('duplicate_policy_rows')
 if len(d['profiles'])!=3 or any(p['enabled']!='True' for p in d['profiles']):raise ValueError('firewall_profiles_not_enabled')
 return d
