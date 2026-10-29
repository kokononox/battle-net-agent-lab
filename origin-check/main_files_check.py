"""Exact full hashes of fixed main files. Read-only, expected build only, no execution."""
import stat,time
from build_check import Reader,install_root,validate_build,safe,fingerprint,Refused
import build_check,official_70448 as ref
BUDGET=160*1024*1024
PER_FILE_LIMIT=128*1024*1024

def blank():
 r=build_check.blank();r.update(schema='wow-official-main-files-check-1',tool_version='6.0',read_budget_bytes=BUDGET,per_file_read_limit_bytes=PER_FILE_LIMIT,read_time_limit_ms=60000,read_timeout_is_sampled=True,components={k:dict(status='not_checked',observed_bytes=None,matched_public_ckey=None)for k in ref.MAIN_FILES},small_helper_files_read=False)
 return r

def assess(root):
 r=blank();reader=Reader(r,budget=BUDGET,deadline=time.monotonic()+60);watched=[]
 try:
  root=install_root(root);info=root/'.build.info';raw,fp=reader.file(info,65536);watched.append((info,fp));validate_build(raw);r['active_build_matched']=True
  for label,filename in ref.MAIN_FILES.items():
   c=r['components'][label]
   try:p=safe(root/'_retail_'/filename)
   except Refused as e:
    if str(e)=='path_missing':c['status']='not_found';continue
    raise
   s=p.stat()
   if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
   c['observed_bytes']=s.st_size
   if s.st_size>PER_FILE_LIMIT:raise Refused('file_size_limit')
   variants=[v for v in ref.MAIN_COMPONENTS[label]if v['size']==s.st_size]
   if not variants:c['status']='size_not_in_reference';continue
   r['client_executable_checked'if label=='client_executable'else'client_loader_checked']=True
   checksum,fp=reader.file(p,s.st_size,digest=True)
   if fp!=fingerprint(s):raise Refused('source_changed')
   watched.append((p,fp));match=next((v for v in variants if v['ckey']==checksum),None)
   if match:c.update(status='content_verified',matched_public_ckey=match['ckey']);r['verified_components']+=1
   else:c['status']='hash_mismatch'
  for path,fp in watched:
   if fingerprint(safe(path).stat())!=fp:raise Refused('source_changed')
  r['all_selected_components_match']=r['verified_components']==len(ref.MAIN_FILES);r['status']='completed'
 except Refused as e:
  r['error_kind']=str(e)
 except Exception:r['error_kind']='io_or_environment_error'
 if r['status']!='completed':
  r['verified_components']=0;r['all_selected_components_match']=False
  for c in r['components'].values():
   if c['status']=='content_verified':c.update(status='invalidated',matched_public_ckey=None)
 return r
