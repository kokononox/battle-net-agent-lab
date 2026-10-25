"""Read only fixed installation artifacts/registry; no execution or repair of downloaded files."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
from completion_rules import assess
root=Path(sys.argv[1]);pf=Path(os.environ['ProgramFiles(x86)'])/'Battle.net'
def read(p):
 try:
  if p.stat().st_size>1048576:return {}
  return json.loads(p.read_text(encoding='utf-8-sig'))
 except Exception:return {}
def safe(p):
 try:
  return p.is_file() and p.resolve().is_relative_to(pf.resolve()) and all(not x.is_symlink() and not getattr(x.lstat(),'st_file_attributes',0)&0x400 for x in [p,*p.parents])
 except OSError:return False
paths={pf/'Battle.net Launcher.exe':'launcher'}
# Derive only already-observed client paths, never execute an arbitrary installed file.
events=root/'private-events.jsonl'
if events.exists() and events.stat().st_size<=1048576:
 for line in events.read_text(encoding='utf-8-sig').splitlines()[:512]:
  try:
   e=json.loads(line);p=Path(e.get('identity',{}).get('image',''))
   if p.name.lower()=='battle.net.exe' and safe(p) and len(paths)<8:paths[p]='client'
  except Exception:pass
artifacts=[]
for p,kind in paths.items():
 item={'kind':kind,'present':safe(p),'signature_accepted':False,'signature_status':'not_attempted'}
 if item['present']:
  try:
   size=p.stat().st_size
   if not 0<size<=67108864:raise ValueError('artifact_size_bound')
   with p.open('rb') as f:item['pe_file']=f.read(2)==b'MZ'
   item['bytes']=size;item['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
   run=subprocess.run([str(root/'OfflineLauncher.exe'),'verify',str(p)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25)
   if run.returncode or len(run.stdout)>4096:raise ValueError('signature_verifier_failed')
   sig=json.loads(run.stdout.decode('utf-8-sig'));item['trust_status']=sig['trust_status'];item['signature_accepted']=sig['trust_status']==0 and sig['expected_blizzard_publisher'] is True;item['signature_status']='verified' if item['signature_accepted'] else 'not_trusted_under_current_gate'
  except Exception:item['signature_status']='verification_incomplete'
 artifacts.append(item)
def expected_uninstaller(p):
 try:
  pd=Path(os.environ['ProgramData'])/'Battle.net'
  roots=[pf.resolve(),pd.resolve()]
  return p.name.lower()=='blizzard uninstaller.exe' and p.is_file() and any(p.resolve().is_relative_to(x) for x in roots) and all(not x.is_symlink() and not getattr(x.lstat(),'st_file_attributes',0)&0x400 for x in [p,*p.parents])
 except OSError:return False
registry={'scope':'fixed_uninstall_locations_readonly','records':[],'query_errors':0}
try:
 import winreg as w
 for hive in (w.HKEY_LOCAL_MACHINE,w.HKEY_CURRENT_USER):
  for flag in (w.KEY_WOW64_32KEY,w.KEY_WOW64_64KEY):
   try:
    with w.OpenKey(hive,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',0,w.KEY_READ|flag) as key:
     for index in range(min(w.QueryInfoKey(key)[0],4096)):
      sub=w.EnumKey(key,index)
      if 'battle.net' not in sub.lower():continue
      with w.OpenKey(key,sub) as entry:
       def value(name):
        try:return str(w.QueryValueEx(entry,name)[0])[:4096]
        except OSError:return ''
       name=value('DisplayName');location=value('InstallLocation');command=value('UninstallString')
       match=re.match(r'^\s*"([^"]+\.exe)"|^\s*(.+?\.exe)(?:\s|$)',command,re.I);exe=Path(next((x for x in match.groups() if x),'')) if match else None
       registry['records'].append({'display_name_matches':name.strip().lower()=='battle.net','install_location_matches':bool(location) and Path(location).resolve()==pf.resolve(),'uninstall_exe_present_inside_install_root':bool(exe and safe(exe)),'uninstaller_present_in_expected_roots':bool(exe and expected_uninstaller(exe)),'uninstaller_root_category':'programfiles_battle_net' if exe and safe(exe) else 'programdata_battle_net' if exe and expected_uninstaller(exe) else 'unconfirmed'})
   except FileNotFoundError:pass
   except OSError:registry['query_errors']+=1
except Exception:registry['query_errors']+=1
processes=read(root/'process-diagnostics.json');ui=read(root/'completion-ui.json');setup_ui=read(root/'ui-result.json')
r={'schema':'installation_completion_evidence_g26_v1','post_job_artifact_check':True,'target_relaunched':False,'ui':ui,'artifacts':artifacts,'uninstall_registry':registry,'assessment':assess(processes,ui,artifacts,registry,setup_ui.get('install_continue_returned') is True)}
(root/'completion-evidence.json').write_text(json.dumps(r))
