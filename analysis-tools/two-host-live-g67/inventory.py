"""Private snapshot; separate live-owner rows from PID zero/TIME_WAIT without raw PIDs."""
import os,json,subprocess
from pathlib import Path
from collections import Counter
ROLES={'agent.exe':'agent','battle.net.exe':'client','battle.net launcher.exe':'launcher','battle.net-setup.exe':'setup','svchost.exe':'Windows_service_host','powershell.exe':'PowerShell','pwsh.exe':'PowerShell','python.exe':'Python','runner.worker.exe':'CI_worker','runner.listener.exe':'CI_listener','msmpeng.exe':'Windows_security'}
STATES={'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTcb','Bound'}
def summarize(raw,known):
 selected=[];public=[];index={int(p['pid']):p for p in raw['processes']}
 for p in raw['processes']:
  role=ROLES.get(p['name'].lower(),'other_process_name_not_exported')
  public.append({'role':role,'signature_status':p['signature_status'],'publisher_class':p.get('publisher_class','not_verified'),'target_TCP_owner':p.get('target_TCP_owner',False),'blizzard_verified':p['blizzard_verified'],'already_observed':p['already_observed']})
  if p['blizzard_verified'] and not p['already_observed'] and p['image_path']:selected.append(p)
 groups=Counter();covered=0;unobserved_live=0;zero=0;timewait=0
 for c in raw['target_IP_TCP']:
  pid=int(c['OwningProcess']);state=c['State'] if c['State'] in STATES else 'other';p=index.get(pid);port=int(c['RemotePort']);role=ROLES.get(p['name'].lower(),'other_process_name_not_exported') if p else 'none_or_unresolved'
  if pid in known:owner='observed_PID';covered+=1
  elif pid==0:owner='PID_zero_no_user_process_owner';zero+=1
  elif p:owner='unobserved_live_process_at_snapshot';unobserved_live+=1
  else:owner='owner_not_in_bounded_process_snapshot'
  if state=='TimeWait':timewait+=1
  groups[(state,owner,role,p.get('publisher_class','not_verified') if p else 'not_applicable',str(port) if port in (80,443,1119) else 'other')]+=1
 return selected,{'processes':public,'target_IP_TCP_rows':len(raw['target_IP_TCP']),'target_IP_TCP_rows_from_observed_PIDs':covered,'target_IP_TCP_rows_from_unobserved_PIDs':len(raw['target_IP_TCP'])-covered,'PID_zero_rows':zero,'TimeWait_rows':timewait,'unobserved_live_process_owner_rows':unobserved_live,'TCP_groups':[dict(zip(['state','owner_class','process_role','publisher_class','remote_port_class'],key),rows=n) for key,n in sorted(groups.items())],'candidate_limit_hit':raw['candidate_limit_hit'],'TCP_limit_hit':raw.get('TCP_limit_hit',False),'coverage_complete':False,'command_lines_collected':False,'raw_paths_or_PIDs_exported':False,'snapshot_races_possible':True}
def snapshot(base,root,known):
 r=subprocess.run(['powershell.exe','-NoProfile','-File',str(base/'Inventory.ps1'),'-Root',str(root),'-Known',','.join(map(str,known))],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if r.returncode:raise RuntimeError('inventory_snapshot_failed')
 raw=json.loads((root/'inventory.PRIVATE.json').read_text(encoding='utf-8-sig'))
 return summarize(raw,known)
