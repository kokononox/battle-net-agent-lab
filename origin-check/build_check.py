"""Read-only SAME-BUILD check of TWO small official components, not whole WoW."""
import csv,hashlib,io,json,os,stat
from pathlib import Path
import official_70448 as ref
from origin_check import safe,fingerprint,Refused
BUDGET=4*1024*1024

def blank():
 return dict(schema='wow-official-component-check-1',tool_version='5.0',status='refused',error_kind=None,expected_product=ref.PRODUCT,expected_version=ref.VERSION,expected_build_key=ref.BUILD_KEY,active_build_matched=False,reference_config_url=ref.CONFIG_URL,reference_install_url=ref.INSTALL_URL,reference_install_ckey=ref.INSTALL_CKEY,reference_install_ekey=ref.INSTALL_EKEY,read_budget_bytes=BUDGET,bytes_read=0,components={k:dict(status='not_checked',observed_bytes=None,matched_public_ckey=None)for k in ref.FILES},verified_components=0,all_selected_components_match=False,client_executable_checked=False,client_loader_checked=False,archive_files_read=False,whole_game_scanned=False,copy_origin_proven=False,hostname_or_account_identity_proven=False,hardware_upload_proven=False,game_executed=False,network_requested=False,game_files_written=False,raw_paths_exported=False,unexpected_hashes_exported=False)

class Reader:
 def __init__(self,r):self.r=r
 def file(self,path,cap,digest=False):
  p=safe(path);s=p.stat()
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
  before=fingerprint(s)
  if s.st_size>cap:raise Refused('file_size_limit')
  if self.r['bytes_read']+s.st_size>BUDGET:raise Refused('read_budget_limit')
  result=hashlib.md5()if digest else bytearray();count=0
  with p.open('rb')as f:
   if fingerprint(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
   while count<s.st_size:
    b=f.read(min(65536,s.st_size-count))
    if not b:raise Refused('source_changed')
    count+=len(b);self.r['bytes_read']+=len(b)
    if digest:result.update(b)
    else:result.extend(b)
   if fingerprint(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
  if fingerprint(safe(p).stat())!=before:raise Refused('source_changed')
  return (result.hexdigest()if digest else bytes(result)),before

def install_root(root):
 root=safe(root)
 if not root.is_dir():raise Refused('directory_required')
 if root.name.casefold()=='_retail_':root=safe(root.parent)
 elif root.name.casefold()=='data'and root.parent.name.casefold()=='data':root=safe(root.parent.parent)
 if not (root/'.build.info').exists():raise Refused('build_info_not_found')
 return root

def validate_build(raw):
 try:
  rows=list(csv.reader(io.StringIO(raw.decode('utf-8-sig')),delimiter='|'))
 except (UnicodeError,csv.Error):raise Refused('build_info_format')
 if not rows or len(rows)>65 or not 1<=len(rows[0])<=32:raise Refused('build_info_format')
 keys=[x.split('!',1)[0].strip()for x in rows[0]]
 if len(set(keys))!=len(keys)or not {'Product','Active','Version','Build Key'}<=set(keys):raise Refused('build_info_format')
 active=[]
 for row in rows[1:]:
  if not any(row):continue
  if len(row)!=len(keys):raise Refused('build_info_format')
  record=dict(zip(keys,row))
  if record['Product']==ref.PRODUCT and record['Active']=='1':active.append(record)
 if len(active)!=1:raise Refused('active_retail_build_ambiguous')
 if active[0]['Version']!=ref.VERSION or active[0]['Build Key']!=ref.BUILD_KEY:raise Refused('build_mismatch')
 return True

def assess(root):
 r=blank();reader=Reader(r);watched=[]
 try:
  root=install_root(root);info=root/'.build.info';raw,fp=reader.file(info,65536);watched.append((info,fp));validate_build(raw);r['active_build_matched']=True
  for label,filename in ref.FILES.items():
   c=r['components'][label]
   try:p=safe(root/'_retail_'/'Utils'/filename)
   except Refused as e:
    if str(e)=='path_missing':c['status']='not_found';continue
    raise
   s=p.stat()
   if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
   c['observed_bytes']=s.st_size;variants=[v for v in ref.COMPONENTS[label]if v['size']==s.st_size]
   if not variants:c['status']='size_not_in_reference';continue
   checksum,fp=reader.file(p,s.st_size,digest=True);watched.append((p,fp));match=next((v for v in variants if v['ckey']==checksum),None)
   if match:c.update(status='content_verified',matched_public_ckey=match['ckey']);r['verified_components']+=1
   else:c['status']='hash_mismatch'
  for path,fp in watched:
   if fingerprint(safe(path).stat())!=fp:raise Refused('source_changed')
  r['all_selected_components_match']=r['verified_components']==len(ref.FILES);r['status']='completed'
 except Refused as e:
  r['error_kind']=str(e)
 except Exception:r['error_kind']='io_or_environment_error'
 if r['status']!='completed':
  r['verified_components']=0;r['all_selected_components_match']=False
  for c in r['components'].values():
   if c['status']=='content_verified':c.update(status='invalidated',matched_public_ckey=None)
 return r
