"""Bounded preinstalled-tool cleanup on an explicitly approved disposable hosted VM.
Never touches OS components, user profiles, Python, .NET, checkout, or game installs.
Missing/reparse/locked trees are skipped; the install's disk guards remain authoritative.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import classic_install as c

GOAL=45*1024**3
ONCE='lab: approved Classic disk preparation 2026-10-18 c24f976b'
# Literal allowlist only: no caller-supplied paths, globbing or directory discovery.
CANDIDATES=(
 ('android-sdk',r'C:\Android\android-sdk'),
 ('temurin-jdk',r'C:\hostedtoolcache\windows\Java_Temurin-Hotspot_jdk'),
 ('microsoft-jdk',r'C:\hostedtoolcache\windows\Java_Microsoft_jdk'),
 ('go-toolcache',r'C:\hostedtoolcache\windows\go'),
 ('ruby-toolcache',r'C:\hostedtoolcache\windows\Ruby'),
)

def approved(env,platform):
 return (c.fresh_environment(env,platform) and env.get('CLASSIC_DISK_PREPARE_ONCE')==ONCE
         and env.get('SystemDrive','').lower()=='c:')

def reparse(path):
 info=path.lstat()
 return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&0x400)

def safe_tree(path):
 # Check lexical ancestors before touching children, never resolve through a junction.
 for parent in reversed((path,*path.parents)):
  if reparse(parent):return False
 if not path.is_dir():return False
 seen=0
 for folder,dirs,files in os.walk(path,followlinks=False):
  for name in dirs+files:
   seen+=1
   if seen>300000 or reparse(Path(folder)/name):return False
 return True

def prepare(env,platform):
 result=dict(schema='classic-disk-preparation-1',status='environment_refused',
             system_free_before_bytes=0,system_free_after_bytes=0,goal_bytes=GOAL,
             minimum_install_free_bytes=c.MIN_FREE,removed=[],skipped=[])
 if not approved(env,platform):return result
 system=Path('C:/')
 result['system_free_before_bytes']=shutil.disk_usage(system).free
 for label,literal in CANDIDATES:
  if shutil.disk_usage(system).free>=GOAL:break
  path=Path(literal)
  try:
   if not safe_tree(path):
    result['skipped'].append(label);continue
   shutil.rmtree(path)
   result['removed'].append(label)
  except (OSError,ValueError):result['skipped'].append(label)
 result['system_free_after_bytes']=shutil.disk_usage(system).free
 result['status']='goal_met' if result['system_free_after_bytes']>=GOAL else 'space_still_low'
 return result

if __name__=='__main__':print(json.dumps(prepare(os.environ,sys.platform)))
