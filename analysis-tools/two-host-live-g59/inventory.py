"""Private snapshot, verified late attach candidates, sanitized public scope report."""
import os,json,subprocess
from pathlib import Path

def snapshot(base,root,known):
 r=subprocess.run(['powershell.exe','-NoProfile','-File',str(base/'Inventory.ps1'),'-Root',str(root),'-Known',','.join(map(str,known))],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if r.returncode:raise RuntimeError('inventory_snapshot_failed')
 raw=json.loads((root/'inventory.PRIVATE.json').read_text(encoding='utf-8-sig'))
 selected=[];public=[]
 for p in raw['processes']:
  role={'agent.exe':'agent','battle.net.exe':'client','battle.net launcher.exe':'launcher','battle.net-setup.exe':'setup'}.get(p['name'].lower(),'other_related_process')
  public.append({'role':role,'signature_status':p['signature_status'],'blizzard_verified':p['blizzard_verified'],'already_observed':p['already_observed']})
  if p['blizzard_verified'] and not p['already_observed'] and p['image_path']:selected.append(p)
 covered=sum(int(c['OwningProcess']) in known for c in raw['target_IP_TCP'])
 return selected,{'processes':public,'target_IP_TCP_rows':len(raw['target_IP_TCP']),'target_IP_TCP_rows_from_observed_PIDs':covered,'target_IP_TCP_rows_from_unobserved_PIDs':len(raw['target_IP_TCP'])-covered,'candidate_limit_hit':raw['candidate_limit_hit'],'coverage_complete':False,'command_lines_collected':False,'raw_paths_exported':False}
