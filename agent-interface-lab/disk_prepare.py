"""Allowlisted, no-link cleanup only on an explicitly approved disposable hosted VM.
No OS components, profiles, Python, .NET, checkout, or game installs are candidates.
Strict evidence contains only tool labels, reason enums, counts, and free-byte readings.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import classic_install as c

GOAL=45*1024**3
ONCE='lab: approved Classic system disk fix 2026-10-18 54bf816e'
MAX_ENTRIES=500000
MAX_SCAN_SECONDS=120
CANDIDATES=(
 ('android-sdk',r'C:\Android\android-sdk'),
 ('temurin-jdk',r'C:\hostedtoolcache\windows\Java_Temurin-Hotspot_jdk'),
 ('microsoft-jdk',r'C:\hostedtoolcache\windows\Java_Microsoft_jdk'),
 ('go-toolcache',r'C:\hostedtoolcache\windows\go'),
 ('ruby-toolcache',r'C:\hostedtoolcache\windows\Ruby'),
 # Installed Visual Studio root is documented by actions/runner-images Windows2025.
 # Delete only the unused compiler toolchain, not the IDE or shared VC++ runtimes.
 ('vs2022-msvc-tools',r'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC'),
)
OUTCOMES={'removed','missing','ancestor_reparse','tree_reparse','not_directory',
          'scan_limit','io_refused','unsupported_entry'}

def approved(env,platform):
 return (c.fresh_environment(env,platform) and env.get('CLASSIC_DISK_PREPARE_ONCE')==ONCE
         and env.get('SystemDrive','').lower()=='c:')

def reparse(path):
 info=path.lstat()
 return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&0x400)

def inspect_tree(path,clock=time.monotonic):
 entries=logical_bytes=0;deadline=clock()+MAX_SCAN_SECONDS
 try:
  # Never resolve through links; reject reparse points in lexical ancestors first.
  for parent in reversed((path,*path.parents)):
   if reparse(parent):return 'ancestor_reparse',0,0
  if not path.is_dir():return 'not_directory',0,0
  def refuse(error):raise error
  for folder,dirs,files in os.walk(path,followlinks=False,onerror=refuse):
   for name in dirs+files:
    entries+=1
    if entries>MAX_ENTRIES or clock()>deadline:return 'scan_limit',min(entries,MAX_ENTRIES),logical_bytes
    child=Path(folder)/name
    if reparse(child):return 'tree_reparse',entries,logical_bytes
    info=child.lstat()
    if stat.S_ISREG(info.st_mode):logical_bytes+=info.st_size
    elif not stat.S_ISDIR(info.st_mode):return 'unsupported_entry',entries,logical_bytes
    if logical_bytes>2**50:return 'scan_limit',entries,2**50
  return 'safe',entries,logical_bytes
 except FileNotFoundError:return 'missing',entries,logical_bytes
 except OSError:return 'io_refused',entries,logical_bytes

def remove_tree(path):
 def readonly(func,child,error):
  # Windows SDK/compiler ZIPs can contain read-only files. Do not override locks,
  # change ACLs, follow junctions or chmod anything outside this exact tree.
  child=Path(child)
  if not isinstance(error,PermissionError):raise error
  child.relative_to(path)
  if reparse(child):raise error
  os.chmod(child,stat.S_IWRITE)
  func(child)
 shutil.rmtree(path,onexc=readonly)

def blank(env):
 return dict(schema='classic-disk-preparation-2',source_commit=env.get('GITHUB_SHA',''),
  run_id=env.get('GITHUB_RUN_ID',''),run_attempt=env.get('GITHUB_RUN_ATTEMPT',''),
  status='environment_refused',system_free_before_bytes=0,system_free_after_bytes=0,
  goal_bytes=GOAL,minimum_install_free_bytes=c.MIN_FREE,attempts=[])

def validate(r):
 if type(r)is not dict or set(r)!=set(blank({})):raise ValueError('disk_schema')
 if r['schema']!='classic-disk-preparation-2' or r['status']not in {'environment_refused','goal_met','space_still_low'}:raise ValueError('disk_enum')
 if type(r['source_commit'])is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit']):raise ValueError('disk_commit')
 if type(r['run_id'])is not str or not re.fullmatch('[0-9]{1,30}',r['run_id'])or r['run_attempt']!='1':raise ValueError('disk_run')
 for key in ('goal_bytes','minimum_install_free_bytes'):
  if type(r[key])is not int or r[key]!=blank({})[key]:raise ValueError('disk_limit')
 for key in ('system_free_before_bytes','system_free_after_bytes'):
  if type(r[key])is not int or not 0<=r[key]<=2**60:raise ValueError('disk_bytes')
 if type(r['attempts'])is not list or len(r['attempts'])>len(CANDIDATES):raise ValueError('disk_attempts')
 labels=[x[0]for x in CANDIDATES];seen=[]
 for a in r['attempts']:
  if type(a)is not dict or set(a)!={'tool','outcome','entries','logical_bytes'}:raise ValueError('disk_attempt_schema')
  if a['tool']not in labels or a['tool']in seen or a['outcome']not in OUTCOMES:raise ValueError('disk_attempt_enum')
  seen.append(a['tool'])
  for key,cap in [('entries',MAX_ENTRIES),('logical_bytes',2**50)]:
   if type(a[key])is not int or not 0<=a[key]<=cap:raise ValueError('disk_attempt_count')
 if seen!=labels[:len(seen)]:raise ValueError('disk_order')
 if r['status']=='goal_met'and r['system_free_after_bytes']<GOAL:raise ValueError('disk_false_goal')
 if r['status']=='environment_refused'and(r['attempts']or r['system_free_before_bytes']or r['system_free_after_bytes']):raise ValueError('disk_refused_evidence')
 return r

def prepare(env,platform):
 result=blank(env)
 if not approved(env,platform):return result
 system=Path('C:/');result['system_free_before_bytes']=shutil.disk_usage(system).free
 for label,literal in CANDIDATES:
  if shutil.disk_usage(system).free>=GOAL:break
  path=Path(literal);outcome,entries,size=inspect_tree(path)
  if outcome=='safe':
   try:remove_tree(path);outcome='removed'
   except (OSError,ValueError):outcome='io_refused'
  result['attempts'].append(dict(tool=label,outcome=outcome,entries=entries,logical_bytes=size))
 result['system_free_after_bytes']=shutil.disk_usage(system).free
 result['status']='goal_met'if result['system_free_after_bytes']>=GOAL else 'space_still_low'
 return validate(result)

if __name__=='__main__':
 result=validate(prepare(os.environ,sys.platform))
 out=Path('output');out.mkdir(exist_ok=True)
 (out/'classic-disk-to-share.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
 print(json.dumps(result))
