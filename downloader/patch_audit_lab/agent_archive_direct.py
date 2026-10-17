"""Native cache on a pinned live data.000 FD under an active owned V8 lock.
No snapshots, marker additions, directory scans, pathname opens by the oracle,
network, write access, Windows execution or general-installation admission.
"""
import fcntl,os,stat,struct,subprocess
from pathlib import Path
import agent_archive_insert as prior
import agent_static_audit as identity
import owned_v8_lock as locks
import patch_audit as a
import source_binding as b

class Observations(list):
 def __init__(self,rows,proof):super().__init__(rows);self.proof=proof

def oracle_identity(path):
 path=b.safe(path,True);w=b.Watch();r=b.json_object(w.read(path.parent/'BUILD-RECEIPT.json',131072))
 for key,value in {'format':'agent-archive-direct-build-1','agent_sha256':identity.AGENT_SHA256,'original_constructor_executed':True,'original_table_insertion_executed':True,'original_bytes_verified_in_elf':True,'pinned_read_only_live_descriptor':True,'pathname_open_in_adapter':False,'descriptor_dup_in_adapter':True,'whole_agent_executed':False,'windows_io_executed':False,'no_rwx':True,'nx_stack':True}.items():a.require(r.get(key)==value,'direct_oracle_receipt')
 a.require(a.sha256(w.read(path,2*1024**2))==r['binary_sha256'],'direct_oracle_digest');w.check();return path

def native(oracle,root,addresses,length=188,read_error=0,open_error=0,read_error_on=0,open_error_on=0):
 import retail_v8_cycle as base
 lease=locks.require(root);root=lease.root;oracle=oracle_identity(oracle)
 a.require(type(addresses)is list and 1<=len(addresses)<=4 and all(type(v)is int and v in (480,668) for v in addresses),'direct_address_profile')
 a.require(type(length)is int and length==188,'direct_read_size_profile')
 for value,limit in ((read_error,0xffffffff),(open_error,0xffffffff),(read_error_on,4),(open_error_on,4)):a.require(type(value)is int and 0<=value<=limit,'direct_error_profile')
 # Full strict layout and pinned source/patch/target policy, not a marker alone.
 view=base.inspect(root);w=b.Watch();raw=w.read(root/'data.000',1024)
 a.require(raw==view['data'],'direct_live_view_mismatch')
 a.require(all(ad+length<=len(raw) for ad in addresses),'direct_live_file_bounds')
 path=root/'data.000';before=w.files[path]
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);a.require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and b.fp(st)==before,'direct_live_descriptor_identity')
  flags=fcntl.fcntl(fd,fcntl.F_GETFL);a.require(flags&os.O_ACCMODE==os.O_RDONLY,'direct_readonly_descriptor')
  request=struct.pack('<Q14I3Q',addresses[0],length,1,read_error,open_error,0,len(addresses),fd,0,0,0,read_error_on,open_error_on,0,0,*(addresses[1:]+[0]*(4-len(addresses))))
  # Inherit the SAME locked open-file-description too: child lifetime retains it.
  proc=subprocess.run([str(oracle)],input=request,capture_output=True,pass_fds=(fd,lease.fd),timeout=5)
  locks.require(root);a.require(b.fp(os.fstat(fd))==before,'direct_live_descriptor_changed');w.check()
  a.require(proc.returncode==0 and not proc.stderr,'direct_native_execution')
  rows=[];pos=0
  for address in addresses:
   a.require(len(proc.stdout)-pos>=148,'direct_trace_short');values=struct.unpack_from('<29I',proc.stdout,pos);row=dict(zip(prior.FIELDS,values));name=proc.stdout[pos+116:pos+148];a.require(b'\0' in name,'direct_trace_filename')
   row['filename']=name.split(b'\0',1)[0].decode('ascii');a.require(row['filename']=='data.000','direct_trace_wrong_filename');pos+=148
   n=row['actual_bytes'];a.require(n<=length and pos+n<=len(proc.stdout),'direct_trace_payload');data=proc.stdout[pos:pos+n];pos+=n
   # Compare actual native bytes to an independent read from the SAME live inode.
   if n:a.require(data==os.pread(fd,n,address),'direct_live_payload_parity')
   rows.append((row,data))
  a.require(pos==len(proc.stdout),'direct_trace_trailing');a.require(b.fp(os.fstat(fd))==before,'direct_live_postcompare_changed');w.check()
  proof={'live_archive_fingerprint':before,'live_archive_sha256':a.sha256(raw),'read_only_descriptor_checked_by_host_and_native':True,'same_live_inode_read_not_snapshot':True,'native_create_adapter':'dup pinned FD, not pathname open','lock_open_description_inherited_by_child':True,'active_owned_lock_verified_before_and_after':True,'file_identity_unchanged':True,'snapshots_created':0,'markers_created':0,'files_written_by_reader':0}
  return Observations(rows,proof)
 finally:os.close(fd)

def compare(oracle,root,addresses,length=188,**kw):
 rows=native(oracle,root,addresses,length,**kw);cached=False;opens=reads=locks_count=allocations=formats=0;head=0xffffffff
 for i,(address,(row,data)) in enumerate(zip(addresses,rows)):
  locks_count+=1;status=0;didread=False;expected=b''
  if not cached:
   opens+=1;formats+=1;err=kw.get('open_error',0) if not kw.get('open_error_on',0) or kw['open_error_on']==opens else 0
   if err:status=2 if err==2 else 24 if err==32 else 8
   else:cached=True;allocations+=1
  if not status:
   didread=True;reads+=1;head=0
   err=kw.get('read_error',0) if not kw.get('read_error_on',0) or kw['read_error_on']==reads else 0
   if err:status=0 if err==38 else 8
   else:
    # Length/bounds were admitted and descriptor remained stable in native().
    expected=data;a.require(len(data)==length,'direct_unexpected_short_read')
  expected_trace={'status':status,'actual_bytes':len(expected),'create_calls':opens,'constructor_calls':allocations,'read_calls':reads,'format_calls':formats,'locks':locks_count,'unlocks':locks_count,'reference0_after':int(cached),'new_reference_after':1 if didread else 0,'new_reference_during_read':2 if didread else 0,'list_head':head,'entry0_hash':0}
  a.require(all(row[k]==v for k,v in expected_trace.items()),'direct_original_model_parity');a.require(data==expected,'direct_model_payload_parity')
 return rows
