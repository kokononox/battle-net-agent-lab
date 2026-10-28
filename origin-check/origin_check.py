"""Read-only local CASC marker checker. Standard library only; no network I/O."""
import hashlib,json,os,re,socket,stat,sys
import format_diagnostics,key_diagnostics
from pathlib import Path
from marker_prefix import block_valid,MAX_PREFIX
ARCH=re.compile(r'data\.([0-9]{3,})',re.IGNORECASE)
class Refused(Exception):pass

def safe(path):
 path=Path(os.path.abspath(path))
 for p in reversed((path,*path.parents)):
  try:s=p.lstat()
  except FileNotFoundError:raise Refused('path_missing')
  if stat.S_ISLNK(s.st_mode)or getattr(s,'st_file_attributes',0)&0x400:raise Refused('link_or_reparse')
  if p!=path and not stat.S_ISDIR(s.st_mode):raise Refused('ancestor_not_directory')
 return path

def fingerprint(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink)
def read_prefix(path):
 path=safe(path);s=path.stat()
 if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
 fp=fingerprint(s)
 with path.open('rb')as f:
  if fingerprint(os.fstat(f.fileno()))!=fp:raise Refused('source_changed')
  raw=f.read(MAX_PREFIX)
  if fingerprint(os.fstat(f.fileno()))!=fp:raise Refused('source_changed')
 if fingerprint(safe(path).stat())!=fp:raise Refused('source_changed')
 return raw,fp

def extract(raw,archive):
 """Return private marker set; callers MUST NOT print its contents."""
 seeds=set();start=0;attempts=0
 while True:
  at=raw.find(b'\x1e\x00\x00\x00\x01\x00',start)
  if at<0:break
  start=at+1;offset=at-16
  if offset<0 or offset+480>len(raw):continue
  attempts+=1
  if attempts>64:raise Refused('candidate_limit')
  key=raw[offset:offset+16][::-1]
  if key[1]==archive and block_valid(raw,offset,key[2:9]):seeds.add(key[2:9])
 return seeds

def inspect(root,batch_start=0):
 if type(batch_start)is not int or batch_start<0 or batch_start>4096 or batch_start%64:raise Refused('invalid_batch_start')
 root=safe(root)
 if not root.is_dir():raise Refused('directory_required')
 child=root/'Data'/'data'
 folder=safe(child)if child.exists()else root
 names=[]
 with os.scandir(folder)as it:
  for item in it:
   names.append(item.name)
   if len(names)>4096:raise Refused('directory_limit')
 selected=[];unsupported=0
 for name in names:
  m=ARCH.fullmatch(name)
  if m:
   if int(m[1])<=255:selected.append((name,int(m[1])))
   else:unsupported+=1
 selected.sort(key=lambda x:(x[1],x[0]));total=len(selected);batch=selected[batch_start:batch_start+64]
 host=socket.gethostname().encode('utf-8');current_digest=hashlib.md5(host+b'data/data').digest();negative_digest=hashlib.md5(host+b'|bounded-negative-control|data/data').digest();current=current_digest[2:9];negative=negative_digest[2:9]
 diagnostics=format_diagnostics.blank();key_diag=key_diagnostics.blank()
 private=set();checked=[];matched=0;read=0
 for name,archive in batch:
  path=folder/name;raw,fp=read_prefix(path);read+=len(raw);format_diagnostics.observe(raw,archive,current,negative,diagnostics);key_diagnostics.observe(raw,archive,current_digest,negative_digest,key_diag);seeds=extract(raw,archive);private.update(seeds);matched+=bool(seeds);checked.append((path,fp))
 for path,fp in checked:
  if fingerprint(safe(path).stat())!=fp:raise Refused('source_changed')
 summary=dict(key_diagnostics=key_diagnostics.validate(key_diag),format_diagnostics=format_diagnostics.validate(diagnostics),batch_start=batch_start,archives_per_batch_limit=64,total_eligible_archives=total,unsupported_archive_ids=unsupported,total_archives_found=total+unsupported,archives_not_checked_this_run=total+unsupported-len(batch),archive_scan_complete=batch_start==0 and len(batch)==total and unsupported==0,more_archives_available=batch_start+len(batch)<total,next_batch_start=batch_start+64 if batch_start+len(batch)<total else None,archives_checked=len(batch),archives_with_supported_crosslink_block=matched,prefix_bytes_read=read,max_prefix_bytes=MAX_PREFIX,marker_variants=len(private),marker_layout_observed=bool(private),matches_current_hostname_prediction=current in private if private else None,scope='bounded_local_archive_prefixes_only',whole_game_scanned=False,account_identity_proven=False,unique_physical_machine_identity_proven=False,game_payload_watermark_proven=False,unforgeable_origin_proven=False,raw_paths_exported=False,raw_hostname_exported=False,identifier_hash_exported=False,network_requested=False,game_files_written=False)
 return summary,private

def main(args,batch_start=0):
 out=dict(schema='casc-offline-origin-check-4',tool_version='4.0',status='refused',error_kind=None,first=None,second=None,two_copy_marker_sets_equal=None,observed_batch_marker_sets_equal=None,comparison_scope='observed_archive_prefix_markers_only',full_file_equality_proven=False)
 try:
  if len(args)not in (1,2):raise Refused('one_or_two_local_directories_required')
  out['first'],first=inspect(args[0],batch_start)
  if len(args)==2:
   out['second'],second=inspect(args[1],batch_start)
   if first and second:
    out['observed_batch_marker_sets_equal']=first==second
    if out['first']['archive_scan_complete']and out['second']['archive_scan_complete']:out['two_copy_marker_sets_equal']=first==second
  out['status']='completed'
 except Refused as e:out['error_kind']=str(e)
 except Exception:out['error_kind']='io_or_environment_error'
 print(json.dumps(out,indent=2));return 0 if out['status']=='completed'else 2
if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
