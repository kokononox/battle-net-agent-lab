import base64,ctypes,hashlib,ipaddress,json,os,secrets,subprocess,sys,time,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
ENDPOINTS=json.loads((BASE/'app/endpoints.json').read_text())
REVIEW_ENDPOINTS=json.loads((BASE/'app/review-endpoints.json').read_text())
assert len(REVIEW_ENDPOINTS)==5 and all(e in ENDPOINTS for e in REVIEW_ENDPOINTS)
LEASE=300
OUTCOMES={'auth_failed','characters_missing','world_failed','world_unstable','world_ok','unclear','cancelled'}

def atomic(path,obj):
 path=Path(path);temp=path.with_suffix('.tmp');temp.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temp,path)

def digest(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def verify_package():
 for n,h in json.loads((BASE/'MANIFEST-SHA256.json').read_text()).items():
  p=Path(n)
  if p.is_absolute() or '..' in p.parts or digest(BASE/p)!=h:raise RuntimeError('package_integrity_failed')

def validate(j):
 i=j['id']
 if len(i)!=32 or any(c not in '0123456789abcdef' for c in i):raise ValueError('invalid_id')
 if j['name']!='WoWEndpointSteps-'+i or j['group']!='WoWEndpointStepsOwner-'+i:raise ValueError('invalid_owner')
 if {k:j[k] for k in ('ip','port','protocol')} not in ENDPOINTS:raise ValueError('unknown_endpoint')
 if not ipaddress.ip_address(j['ip']).is_global:raise ValueError('public_endpoint_required')
 if Path(j['program']).name.lower()!='wow.exe':raise ValueError('invalid_program')
 return j

STAGES={'read_journal','check_ownership','check_profiles','check_service','validate_endpoint','create_rule','read_persistent_rule','read_application_filter','read_address_filter','read_port_filter','verify_persistent_rule','wait_effective_policy','remove_owned_rule','verify_rule_absence','validate_action','powershell_timeout','powershell_output','powershell_launch'}
REASONS={'operation_failed','invalid_owner','ownership_mismatch','profiles_not_already_enabled','service_not_running','existing_rule_restore_first','invalid_endpoint','selected_program_missing','persistent_rule_count_mismatch','persistent_filter_mismatch','rule_not_effective_after_readback_wait','absence_not_verified','invalid_action','timeout','invalid_output','launch_failed'}
CHECKS={'owner','enabled','action','direction','application_filter_count','address_filter_count','port_filter_count','program','remote_address','protocol','remote_port'}

def record_fw_error(action,raw):
 stage=raw.get('stage') if raw.get('stage') in STAGES else 'powershell_output'
 reason=raw.get('reason') if raw.get('reason') in REASONS else 'operation_failed'
 safe={'schema':'wow-firewall-error-1','version':'0.1.6','action':action,'stage':stage,'reason':reason,'hresult':raw.get('hresult') if type(raw.get('hresult')) is int else None,'native_error':raw.get('native_error') if type(raw.get('native_error')) is int else None,'category':raw.get('category') if raw.get('category') in {'NotSpecified','OpenError','CloseError','DeviceError','DeadlockDetected','InvalidArgument','InvalidData','InvalidOperation','InvalidResult','InvalidType','MetadataError','NotImplemented','NotInstalled','ObjectNotFound','OperationStopped','OperationTimeout','SyntaxError','ParserError','PermissionDenied','ResourceBusy','ResourceExists','ResourceUnavailable','ReadError','WriteError','FromStdErr','SecurityError','ProtocolError','ConnectionError','AuthenticationError','LimitsExceeded','QuotaExceeded','NotEnabled'} else None,'checks':{k:v for k,v in raw.get('checks',{}).items() if k in CHECKS and type(v) is bool},'raw_error_or_program_path_exported':False}
 try:
  out=BASE/'output';out.mkdir(exist_ok=True);atomic(out/('firewall-error-'+uuid.uuid4().hex+'.json'),safe)
 except Exception:pass
 raise RuntimeError('firewall_'+action+'_failed_'+stage)

def firewall(action,path):
 validate(json.loads(Path(path).read_text()))
 if action not in ('probe','add','remove'):raise ValueError('invalid_action')
 env=os.environ.copy();env['WOW_STEPS_ACTION']=action;env['WOW_STEPS_JOURNAL']=str(path)
 command="& ([scriptblock]::Create([System.IO.File]::ReadAllText('"+str(BASE/'app/firewall.ps1').replace("'","''")+"')))"
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 try:
  r=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(command.encode('utf-16le')).decode()],env=env,capture_output=True,timeout=60,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 except subprocess.TimeoutExpired:
  return record_fw_error(action,{'stage':'powershell_timeout','reason':'timeout'})
 except OSError:
  return record_fw_error(action,{'stage':'powershell_launch','reason':'launch_failed'})
 try:
  result=json.loads(r.stdout.decode('utf-8-sig'))
  if not isinstance(result,dict):raise ValueError()
 except (UnicodeError,ValueError):
  return record_fw_error(action,{'stage':'powershell_output','reason':'invalid_output'})
 if r.returncode or result.get('ok') is not True:return record_fw_error(action,result)
 return result

def selected_exe():
 import ctypes.wintypes as W
 class OFN(ctypes.Structure):
  _fields_=[('lStructSize',W.DWORD),('hwndOwner',W.HWND),('hInstance',W.HINSTANCE),('lpstrFilter',W.LPCWSTR),('lpstrCustomFilter',W.LPWSTR),('nMaxCustFilter',W.DWORD),('nFilterIndex',W.DWORD),('lpstrFile',W.LPWSTR),('nMaxFile',W.DWORD),('lpstrFileTitle',W.LPWSTR),('nMaxFileTitle',W.DWORD),('lpstrInitialDir',W.LPCWSTR),('lpstrTitle',W.LPCWSTR),('Flags',W.DWORD),('nFileOffset',W.WORD),('nFileExtension',W.WORD),('lpstrDefExt',W.LPCWSTR),('lCustData',ctypes.c_ssize_t),('lpfnHook',ctypes.c_void_p),('lpTemplateName',W.LPCWSTR),('pvReserved',ctypes.c_void_p),('dwReserved',W.DWORD),('FlagsEx',W.DWORD)]
 buf=ctypes.create_unicode_buffer(32768);o=OFN();o.lStructSize=ctypes.sizeof(o);o.lpstrFilter='World of Warcraft\0Wow.exe\0\0';o.lpstrFile=ctypes.cast(buf,W.LPWSTR);o.nMaxFile=len(buf);o.lpstrTitle='Choose the Wow.exe you will test';o.Flags=0x1000|0x80000|0x8
 dll=ctypes.WinDLL('comdlg32');dll.GetOpenFileNameW.argtypes=[ctypes.POINTER(OFN)]
 if not dll.GetOpenFileNameW(ctypes.byref(o)):raise RuntimeError('selection_cancelled')
 p=Path(buf.value).resolve()
 if p.name.lower()!='wow.exe' or not p.is_file():raise RuntimeError('select_Wow_exe')
 return p

class Session:
 def __init__(self,program=None,root=BASE,fw=firewall,guard=None,monitor=None,monitor_stop=None):
  self.root=Path(root);self.private=self.root/'private-state';self.private.mkdir(exist_ok=True)
  self.output=self.root/'output';self.output.mkdir(exist_ok=True)
  self.program=program;self.fw=fw;self.guard=guard;self.monitor=monitor;self.monitor_stop=monitor_stop;self.current=None;self.records=[];self.phase='idle';self.error=None;self.report_id=uuid.uuid4().hex;self.hash=digest(program) if program else None
 def recover(self):
  failures=[]
  for p in self.private.glob('session-*.json'):
   try:
    j=validate(json.loads(p.read_text()));self.fw('remove',p)
    if j.get('add_outcome_uncertain') and time.time()<j['expires'] and not p.with_suffix('.restored').exists():raise RuntimeError('wait_for_watchdog_lease_then_Restore')
    # A failed journal never prevents cleanup attempts on the remaining rules.
    p.unlink();p.with_suffix('.ready').unlink(missing_ok=True);p.with_suffix('.restored').unlink(missing_ok=True)
   except Exception as e:failures.append(e)
  if failures:raise failures[0]
 def start(self,index,consent):
  if self.phase!='idle' or self.current is not None:raise RuntimeError('restore_previous_first')
  if consent is not True:raise RuntimeError('explicit_consent_required')
  if not self.program or digest(self.program)!=self.hash:raise RuntimeError('selected_exe_changed')
  if type(index) is not int or not 0<=index<len(ENDPOINTS):raise ValueError('invalid_endpoint')
  if ENDPOINTS[index]['protocol']!='TCP' or ENDPOINTS[index]['ip']=='37.244.29.11':raise RuntimeError('not_in_six_endpoint_review')
  i=uuid.uuid4().hex;j={'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(self.program),**ENDPOINTS[index],'expires':time.time()+LEASE,'parent_pid':os.getpid()}
  p=self.private/('session-'+i+'.json');atomic(p,j);self.current=(p,j,index);self.phase='arming'
  try:
   self.fw('probe',p)
   if self.guard:self.guard(p)
   else:raise RuntimeError('watchdog_unavailable')
   if time.time()>=j['expires']-30:raise RuntimeError('lease_already_expiring')
   try:self.fw('add',p)
   except Exception:
    j['add_outcome_uncertain']=True;atomic(p,j);raise
   if self.monitor:self.monitor(p)
   self.phase='blocked';self.error=None
  except Exception:
   try:self.restore('setup_failed')
   except Exception:self.phase='recovery_required'
   raise
 def restore(self,why='manual'):
  if self.current:
   p,j,index=self.current
   monitor_result={'status':'not_collected'}
   if self.monitor_stop:
    try:monitor_result=self.monitor_stop(p)
    except Exception:monitor_result={'status':'monitor_inconclusive'}
   self.fw('remove',p)
   if j.get('add_outcome_uncertain') and time.time()<j['expires'] and not p.with_suffix('.restored').exists():
    self.phase='recovery_required';raise RuntimeError('add_uncertain_wait_for_watchdog_lease')
   self.records.append({'endpoint':ENDPOINTS[index],'selected_exe_sha256':self.hash,'started_utc_epoch':j['expires']-LEASE,'restored_utc_epoch':time.time(),'reason':why,'connection_monitor':monitor_result,'rule_absence_verified':True,'packet_block_verified':False,'observation':None,'baseline_restored':None})
   p.unlink(missing_ok=True);p.with_suffix('.ready').unlink(missing_ok=True);p.with_suffix('.restored').unlink(missing_ok=True);self.current=None;self.phase='baseline';self.save()
 def observe(self,value,fresh_launch_reported=False):
  if value not in OUTCOMES:raise ValueError('invalid_observation')
  if self.phase!='blocked' or not self.current:raise RuntimeError('no_active_test')
  self.restore('observation_saved');self.records[-1]['observation']=value;self.records[-1]['fresh_launch_user_reported']=(fresh_launch_reported is True);self.save()
 def baseline(self,value):
  if self.phase!='baseline' or value not in ('yes','no','unknown'):raise ValueError('baseline_required')
  self.records[-1]['baseline_restored']=value;self.save()
  if value=='yes':self.phase='idle';self.error=None
  else:self.error='baseline_not_restored_stop_tests'
 def save(self):
  atomic(self.output/('endpoint-results-'+self.report_id+'.json'),{'schema':'wow-endpoint-steps-1','version':'0.1.6','selected_exe_sha256':self.hash,'records':self.records,'limits':['User-selected observations, not automatic login detection.','Rule configuration/absence checks are not packet-level blocking proof, especially with VPN/custom stacks.','No TLS contents, domain binding, CPU/BIOS determination or raw capture.','Existing sessions, retries, caches and changing IPs can affect results.'],'account_or_credentials_collected':False,'hosts_vpn_other_firewall_rules_modified':False})
 def status(self):
  remaining=0;endpoint=None
  if self.current:
   p,j,index=self.current;remaining=max(0,int(j['expires']-time.time()));endpoint=ENDPOINTS[index]
   if p.with_suffix('.restored').exists() or remaining==0:
    try:self.restore('watchdog_or_lease_expired')
    except Exception:self.phase='recovery_required';self.error='restore_failed_use_restore_cmd'
  return {'phase':self.phase,'remaining':remaining,'endpoint':endpoint,'records':self.records,'error':self.error,'program_selected':self.program is not None}
