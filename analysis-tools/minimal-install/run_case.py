"""Disposable hosted-Windows-only installation pilot. No firewall mutation, login, game request or raw log publication."""
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,tempfile,time
from model import *
import native_version
from datetime import datetime,timezone
def utc_now():return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
BASE=Path(__file__).resolve().parents[2]
OUT=Path('output')/('minimal-install-c0c-'+(os.environ.get('BNET_REPLICA') if os.environ.get('BNET_REPLICA') in REPLICAS else 'invalid')+'.json')
def write(r):
 validate(r);OUT.parent.mkdir(exist_ok=True);data=json.dumps(r,ensure_ascii=False,indent=2).encode();assert len(data)<=1048576
 tmp=OUT.with_suffix('.tmp');tmp.write_bytes(data);os.replace(tmp,OUT)
def registry_checks(root):
 import winreg
 state='unobserved'
 result=dict(registry_key_found=False,registry_location_match=False,registry_version_present=False)
 for hive in (winreg.HKEY_LOCAL_MACHINE,winreg.HKEY_CURRENT_USER):
  for view in (winreg.KEY_WOW64_32KEY,winreg.KEY_WOW64_64KEY):
   try:
    with winreg.OpenKey(hive,r'Software\Microsoft\Windows\CurrentVersion\Uninstall\Battle.net',0,winreg.KEY_READ|view) as key:
     def value(name):
      try:return winreg.QueryValueEx(key,name)[0]
      except OSError:return None
     if value('DisplayName')!='Battle.net':continue
     result['registry_key_found']=True;location=value('InstallLocation');version=value('DisplayVersion')
     if isinstance(location,str) and Path(location).resolve()==root.resolve():
      result['registry_location_match']=True
      if isinstance(version,str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,5}',version):result['registry_version_present']=True;state='accepted'
      elif state!='accepted':state='missing' if version is None else 'wrong_type' if not isinstance(version,str) else 'format_rejected'
   except OSError:pass
 return result,state

def footprint(root,obs,env):
 result,version_state=registry_checks(root);result.update(signed_launcher=False,signed_client=False);binaries=[];paths={}
 if not root.exists() or obs.is_reparse(root):return result,binaries,'',version_state
 count=0;started=time.monotonic()
 for folder,dirs,files in os.walk(root,followlinks=False):
  depth=len(Path(folder).relative_to(root).parts);dirs[:]=[d for d in dirs if depth<2 and not obs.is_reparse(Path(folder)/d)]
  for name in files:
   count+=1
   if count>2500 or time.monotonic()-started>10:break
   kind={'battle.net launcher.exe':'launcher','battle.net.exe':'client'}.get(name.lower())
   if not kind or kind in paths:continue
   path=Path(folder)/name
   if obs.is_reparse(path) or not 0<path.stat().st_size<=128*1024**2:continue
   data=path.read_bytes();digest=hashlib.sha256(data).hexdigest();sig=obs.signature(path,env);accepted=sig['accepted_for_execution'];version,vstate=native_version.query(path)
   if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:accepted=False;version='';vstate='unstable_file'
   binaries.append(dict(kind=kind,sha256=digest,bytes=len(data),signature_accepted=accepted,file_version=version,version_status=vstate));paths[kind]=True
   result['signed_'+kind]=accepted
  if count>2500 or time.monotonic()-started>10:break
 return result,binaries,hashlib.sha256(json.dumps(binaries,sort_keys=True).encode()).hexdigest(),version_state

def main():
 # No report/disk changes before the hosted-runner guard. No portable EXE is released from this pilot.
 if not authorized(os.environ,sys.platform):raise SystemExit('disposable_hosted_approved_case_required')
 r=blank(os.environ);write(r);process=None;env=None;obs=None;started=None
 try:
  sys.path.insert(0,str(BASE/'scripts'));import observe_agent as obs
  import native_gui,ui_accessibility,language_step,install_step,agent_state
  env=obs.clean_environment(os.environ);r['phase']='baseline';root=Path(os.environ['ProgramFiles(x86)'])/'Battle.net'
  roots=[root,Path(os.environ['ProgramData'])/'Battle.net',Path(os.environ['LOCALAPPDATA'])/'Battle.net']
  if obs.snapshot(env).get('processes') or any(p.exists() for p in roots):raise obs.LabError('preexisting_battlenet_state_refused')
  r['phase']='native_gate';ui_accessibility.smoke_check();r['native_ui_gate']=True;write(r)
  with tempfile.TemporaryDirectory(prefix='bnet-minimal-c0c-',dir=os.environ['RUNNER_TEMP'],ignore_cleanup_errors=True) as tmp:
   work=Path(tmp);setup=work/'Battle.net-Setup.exe';r['phase']='download';download=obs.fetch_setup(setup);r['phase']='identity';sig=obs.signature(setup,env)
   r['installer']=dict(sha256=download['sha256'],bytes=download['bytes'],signature_accepted=sig['accepted_for_execution'],matches_pin=download['sha256']==SETUP_SHA and download['bytes']==SETUP_BYTES);write(r)
   if not sig['accepted_for_execution']:raise obs.LabError('installer_signature_refused')
   if not r['installer']['matches_pin']:raise obs.LabError('approved_installer_changed_no_execution')
   r['phase']='launch';process=subprocess.Popen([str(setup)],cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);r['target_launched']=True;r['started_at']=utc_now();started=time.monotonic();r['phase']='observe';write(r)
   endpoints={};seen_processes=set();last_gui=-20;last_foot=-20;layout_since=None;last_hash='';raw={'processes':[]};gui_signals={};last_setup_absent=False
   while time.monotonic()-started<420 and r['samples']<240:
    elapsed=int(time.monotonic()-started);r['observer_seconds']=elapsed
    try:raw=obs.snapshot(env);sample=obs.safe_snapshot(raw,elapsed)
    except Exception:r['snapshot_errors']+=1;time.sleep(3);continue
    r['samples']+=1;by_pid={x['pid']:x['name'] for x in sample['processes']};setup_rows=[x for x in sample['processes'] if x['name']=='battle.net-setup.exe'];last_setup_absent=not setup_rows
    for p in sample['processes']:
     key=(p['pid'],p['name'])
     if key not in seen_processes:seen_processes.add(key);r['known_process_counts'][p['name']]=r['known_process_counts'].get(p['name'],0)+1
    for c in sample['connections']:
     key=(by_pid.get(c['pid']),c['remote_address'],c['remote_port'])
     if key[0] is None:continue
     if key not in endpoints and len(endpoints)>=512:r['endpoints_truncated']=True;continue
     endpoints[key]=endpoints.get(key,0)+1
    r['public_endpoints']=[dict(process_name=k[0],ip=k[1],port=k[2],samples=n) for k,n in sorted(endpoints.items())]
    if elapsed-last_gui>=12:
     last_gui=elapsed;targets=[]
     try:
      gui=native_gui.inspect(set(by_pid),elapsed,on_visible_targets=lambda x:targets.extend(x));gui_signals=agent_state.ui_signals(gui)
      r['ui_signal_last']=gui_signals.copy()
      for k,value in gui_signals.items():r['ui_signal_seen'][k]|=value
      if gui.get('accessibility',{}).get('status')!='ok' or gui.get('probe_errors'):r['gui_errors']+=1
      pid=install_step.setup_pid(sample['processes'],process.pid)
      if pid and gui_signals['language'] and not r['language_attempted'] and not r['install_attempted']:
       r['language_attempted']=True;r['language_status']='pending';write(r);out=language_step.run(targets,pid,setup,authorized=True);r['language_status']=out['status']
       if out['outcome_uncertain']:raise obs.LabError('language_action_uncertain_no_retry')
      elif pid and not gui_signals['language'] and not gui_signals['legal'] and not gui_signals['account'] and not r['install_attempted'] and r['native_options_probes']<30:
       # Do not depend on loose UI marker heuristics to find the options page.
       # The existing native helper verifies the exact six-control page, image and
       # Blizzard signature before a single Continue; mismatch has no action.
       r['native_options_probes']+=1;r['native_options_last_status']='pending';write(r)
       try:out=install_step.run(targets,pid,setup,authorized=True)
       except Exception:raise obs.LabError('native_options_probe_exception_no_retry')
       r['native_options_last_status']=out['status']
       r['install_attempted']=out['continue_attempted'] or out['outcome_uncertain']
       if r['install_attempted']:r['install_status']=out['status']
       if out['outcome_uncertain']:raise obs.LabError('install_action_uncertain_no_retry')
     except obs.LabError:raise
     except Exception:r['gui_errors']+=1
    if elapsed-last_foot>=15:
     last_foot=elapsed;checks,binaries,layout_hash,version_state=footprint(root,obs,env);r['client_binaries']=binaries;r['registry_version_state']=version_state
     ready=layout_ready(checks)
     if ready and layout_hash==last_hash:
      if layout_since is None:layout_since=elapsed
     else:layout_since=elapsed if ready else None
     last_hash=layout_hash;checks['setup_absent']=last_setup_absent;checks['stable_layout_20_seconds']=layout_since is not None and elapsed-layout_since>=20;r['install_checks']=checks
     if installed(checks,r['target_launched']) and not r['snapshot_errors']:
      r['status']='installed_by_defined_gate';break
    write(r);time.sleep(3)
   if r['status']!='installed_by_defined_gate':r['status']='bounded_install_not_verified'
   # The disposable VM, not a persistent user installation, is the isolation boundary for this pilot.
   r['phase']='cleanup';r['cleanup_attempted']=True;write(r);obs.stop_observed(obs.snapshot(env),env)
   if process.poll() is None:subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False)
   r['phase']='complete'
 except Exception as e:
  r['status']='stopped';code=str(e);r['error_code']=code if re.fullmatch('[a-z0-9_]{1,100}',code) else 'pilot_failed_no_install_success_claim'
 finally:
  if r['target_launched'] and not r['cleanup_attempted']:
   r['cleanup_attempted']=True
   try:obs.stop_observed(obs.snapshot(env),env)
   except Exception:pass
   if process is not None and process.poll() is None:
    try:subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False)
    except Exception:pass
  if started is not None:r['observer_seconds']=min(700,int(time.monotonic()-started))
  if r['target_launched']:r['ended_at']=utc_now()
  write(r);print(json.dumps(dict(status=r['status'],error_code=r['error_code'],target_launched=r['target_launched'],case=CASE)))
if __name__=='__main__':main()
