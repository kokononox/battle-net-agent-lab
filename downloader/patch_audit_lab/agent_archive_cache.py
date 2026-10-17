"""Original archive open-manager and hash/cache/retain/LRU/release chain.

Constructor allocation/insertion remains an explicit adapter. Actual cache-miss
filename routing enters original file_open_route/win_open; CreateFileW is adapted
to Linux read-only openat. Write/create modes are denied, never downgraded.
Formatter/UTF conversion, normal frames and single-thread locks are adapters.
"""
import os,struct,subprocess
from pathlib import Path
import agent_archive_io as old
import agent_span_reader as span_reader
import agent_static_audit as identity
import source_binding as b
import patch_audit as a
import synthetic_casc_format as fmt
FIELDS=('status','actual_bytes','manager_calls','derived_archive','read_calls','new_reference_after','constructor_mode','offset_low','offset_high','requested_bytes','descriptor','lower_error_logs','locks','unlocks','constructor_calls','format_calls','create_calls','desired_access','disposition','share_mode','attributes','reference0_after','reference1_after','list_head','format_return','entry0_hash','reference0_during_read','reference1_during_read','new_reference_during_read')
def mix32(v):
 v=(v^(v>>16))*0x85ebca6b&0xffffffff;v=(v^(v>>13))*0xc2b2ae35&0xffffffff;return (v^(v>>16))&0xffffffff
def key_hash(low,flag):
 h=mix32(low);return (h^((mix32(flag)+0x9e3779b9+(h<<6)+(h>>2))&0xffffffff))&0xffffffff

def inputs(address,length,mode=1,scenario=0,read_error=0,open_error=0,format_override=0,fast=0):
 old.inputs(address,length,mode,read_error,open_error)
 for v,limit,label in ((scenario,6,'scenario'),(format_override,0xffffffff,'format_override'),(fast,1,'fast')):a.require(type(v)is int and 0<=v<=limit,'cache_'+label+'_profile')

def oracle_identity(oracle):
 oracle=b.safe(Path(oracle),True);w=b.Watch();r=b.json_object(w.read(oracle.parent/'BUILD-RECEIPT.json',65536));a.require(r.get('format')=='agent-archive-cache-build-1' and r.get('agent_sha256')==identity.AGENT_SHA256 and r.get('original_open_manager_executed') is True and r.get('original_constructor_executed') is False and r.get('windows_io_executed') is False and r.get('original_bytes_verified_in_elf') is True and r.get('no_rwx') is True and r.get('nx_stack') is True,'cache_oracle_receipt');a.require(a.sha256(w.read(oracle,2*1024**2))==r.get('binary_sha256'),'cache_oracle_digest');w.check();return oracle

def selected_paths(root,address,cache_paths):
 ar=(address>>30)&0xffffffff;p=root/f'data.{ar:03d}'
 if cache_paths is None:cache_paths=(p,p)
 a.require(type(cache_paths) in (tuple,list) and len(cache_paths)==2,'cache_two_explicit_paths');return p,tuple(Path(v) for v in cache_paths)

def native(oracle,root,address,length,mode=1,scenario=0,read_error=0,open_error=0,format_override=0,fast=0,cache_paths=None):
 inputs(address,length,mode,scenario,read_error,open_error,format_override,fast);oracle=oracle_identity(oracle);root=b.safe(root);a.require(root.is_dir(),'cache_owned_directory_required');p,paths=selected_paths(root,address,cache_paths);w=b.Watch();fds=[];df=None
 # Native openat may only open the generated final component with O_NOFOLLOW.
 # Precheck existing selected file to reject hardlinks/reparse/symlink paths.
 if p.exists() or p.is_symlink():w.file(p)
 try:
  df=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  a.require(b.fp(os.fstat(df))==b.fp(root.stat()),'cache_directory_identity')
  if scenario:
   for item in paths:
    item=w.file(item);fd=os.open(item,os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);a.require(b.fp(os.fstat(fd))==w.files[item],'cache_descriptor_identity')
  fd0,fd1=fds if fds else (0,0)
  proc=subprocess.run([str(oracle)],input=struct.pack('<Q10I',address,length,mode,read_error,open_error,df,scenario,fd0,fd1,format_override,fast),capture_output=True,pass_fds=tuple(fds+[df]),timeout=5)
  a.require(b.fp(os.fstat(df))==b.fp(root.stat()),'cache_directory_changed')
  for fd,item in zip(fds,paths):a.require(b.fp(os.fstat(fd))==w.files[b.safe(item,True)],'cache_descriptor_changed')
 finally:
  for fd in fds:os.close(fd)
  if df is not None:os.close(df)
 w.check();a.require(proc.returncode==0 and not proc.stderr and len(proc.stdout)>=148,'cache_native_execution');r=dict(zip(FIELDS,struct.unpack('<29I',proc.stdout[:116])));name=proc.stdout[116:148];a.require(b'\0' in name,'cache_filename_trace');r['filename']=name.split(b'\0',1)[0].decode('ascii');data=proc.stdout[148:];a.require(len(data)==r['actual_bytes'] and len(data)<=length,'cache_output_size');return r,data

def compare(oracle,root,address,length,mode=1,scenario=0,read_error=0,open_error=0,format_override=0,fast=0,cache_paths=None):
 inputs(address,length,mode,scenario,read_error,open_error,format_override,fast);root=b.safe(root);p,paths=selected_paths(root,address,cache_paths);w=b.Watch()
 for item in {p,*paths}:
  if item.exists() or item.is_symlink():w.file(item)
 r,data=native(oracle,root,address,length,mode,scenario,read_error,open_error,format_override,fast,cache_paths)
 ar=(address>>30)&0xffffffff;e={n:0 for n in FIELDS};low=(ar+1)&0xffffffff if scenario==2 else ar;e.update(derived_archive=ar,new_reference_after=2,reference0_after=1,reference1_after=1,list_head=0 if scenario else 2,entry0_hash=key_hash(low,1 if scenario==3 else 0),filename='')
 gate=old.range_model(address,length);read=False;hit=scenario in (1,5,6)
 if not gate['valid']:e['status']=10
 elif length:
  e.update(manager_calls=1,locks=1,unlocks=1)
  if hit:
   e['list_head']=1 if scenario==5 else 0;read=True
  else:
   e.update(format_calls=1,filename=f'data.{ar:03d}',format_return=format_override or len(f'data.{ar:03d}'))
   if e['format_return']>=780:e['status']=10
   else:
    e.update(constructor_calls=1,constructor_mode=4 if mode else 1,create_calls=1,desired_access=0x80000000 if mode else 0xc0000000,disposition=3 if mode else 4,share_mode=1 if mode and fast else 7,attributes=128)
    if not mode:e['status']=5
    elif open_error:e['status']=open_error
    elif not p.exists():e['status']=2
    else:read=True
  if read:
   e.update(read_calls=1,offset_low=address&0x3fffffff,requested_bytes=length,descriptor=r['descriptor'],reference0_during_read=2 if scenario in (1,6) else 1,reference1_during_read=2 if scenario==5 else 1,new_reference_during_read=2)
   if not hit:e['new_reference_after']=1
   if read_error not in (0,38):e.update(status=8,lower_error_logs=1)
   elif not read_error:
    target=paths[1] if scenario==5 else paths[0] if hit else p;target=w.file(target);fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
     a.require(b.fp(os.fstat(fd))==w.files[target],'cache_compare_identity');expected=os.pread(fd,length,address&0x3fffffff)
    finally:os.close(fd)
    a.require(data==expected,'cache_actual_file_selection_parity');e['actual_bytes']=len(expected)
 a.require(r==e,'cache_original_model_parity');w.check();return r,data

def read_numbered(oracle,span_oracle,files,address,size,ekey,decoded_size,ckey,scenario=0):
 a.key(ekey);a.key(ckey);a.require(type(address)is int and 0<=address<1023*(1<<30),'cache_reader_address_profile');a.require(type(size)is int and 30<size<=4096,'cache_reader_size_profile');ar=address>>30;off=address&0x3fffffff;a.require(off>=480 and off+size<=1<<30,'cache_reader_segment_bounds');a.require(type(files)is dict and ar in files,'cache_explicit_archive_required');p=Path(files[ar]);a.require(p.name==f'data.{ar:03d}','cache_numbered_filename');w=b.Watch();raw=w.read(p,2*1024**2)
 r,chunk=compare(oracle,p.parent,address,size,scenario=scenario);a.require(r['status']==0 and r['actual_bytes']==size,'cache_exact_read_required');a.require(chunk==raw[off:off+size],'cache_snapshot_parity');parsed=span_reader.compare(span_oracle,chunk[:30],address,size);a.require(parsed['valid'],'cache_original_header_rejected');rec=bytes.fromhex(parsed['record']);addr,stored=struct.unpack_from('<QQ',rec,16);a.require(rec[:16].hex()==ekey and addr==address and stored==size and rec[32]==0,'cache_key_size_flag');a.require(parsed['archive']==ar and parsed['payload_offset']==off+30,'cache_original_address_mismatch');decoded,_=fmt.read_span(chunk,ekey,decoded_size,ckey,ar,off);w.check()
 return {'format':'agent-archive-cache-bridge-1','archive':ar,'filename':p.name,'absolute_address':address,'payload_offset':off+30,'span':size,'encoded_sha256':a.sha256(chunk[30:]),'decoded_bytes':len(decoded),'decoded_md5':a.md5(decoded),'cache_scenario':scenario,'original_manager_and_cache_executed':True,'cache_hit':scenario in (1,5,6),'original_file_open_route_executed':bool(r['constructor_calls']),'original_constructor_allocation_insertion_executed':False,'original_retain_release_executed':True,'os_boundary':'CreateFileW/ReadFile adapted to read-only Linux openat/pread64','decode_implementation':'independent Python','whole_agent_executed':False,'windows_executed':False,'installation_ready':False}
