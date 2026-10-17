"""Bounded original Agent constructor/hash insertion experiment, never a game updater.
Only explicit marked research fixtures. Linux read-only OS adapters; no Windows,
eviction, growth, allocator failure recovery, high-level object reader or BLTE proof.
"""
import json,os,struct,subprocess
from pathlib import Path
import agent_archive_io as old
import agent_archive_cache as prior
import agent_static_audit as identity
import patch_audit as a
import source_binding as b
FIELDS=prior.FIELDS
MARKER='.archive-insert-research.json'
def oracle_identity(path):
 path=b.safe(Path(path),True);w=b.Watch();r=b.json_object(w.read(path.parent/'BUILD-RECEIPT.json',131072))
 for k,v in {'format':'agent-archive-insert-build-1','agent_sha256':identity.AGENT_SHA256,'original_constructor_executed':True,'original_table_insertion_executed':True,'original_bytes_verified_in_elf':True,'whole_agent_executed':False,'windows_io_executed':False,'no_rwx':True,'nx_stack':True}.items():a.require(r.get(k)==v,'insert_oracle_receipt')
 a.require(a.sha256(w.read(path,2*1024**2))==r['binary_sha256'],'insert_oracle_digest');w.check();return path

def native(oracle,root,addresses,length,mode=1,read_error=0,open_error=0,read_error_on=0,open_error_on=0,format_override=0,fast=0,allocation_trap_on=0):
 oracle=oracle_identity(oracle);root=b.safe(Path(root));w=b.Watch();marker=b.json_object(w.read(root/MARKER,4096));a.require(marker=={'format':'archive-insert-owned-fixture-1'},'insert_fixture_marker')
 a.require(type(addresses)is list and 1<=len(addresses)<=4,'insert_read_count')
 for ad in addresses:old.inputs(ad,length,mode,read_error,open_error)
 for v,limit in [(read_error_on,4),(open_error_on,4),(allocation_trap_on,4),(format_override,0xffffffff),(fast,1)]:a.require(type(v)is int and 0<=v<=limit,'insert_control_profile')
 for ar in {ad>>30 for ad in addresses}:
  p=root/f'data.{ar:03d}'
  if p.exists() or p.is_symlink():w.file(p)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  a.require(b.fp(os.fstat(fd))==b.fp(root.stat()),'insert_directory_identity')
  payload=struct.pack('<Q14I3Q',addresses[0],length,mode,read_error,open_error,fd,len(addresses),0,0,format_override,fast,read_error_on,open_error_on,allocation_trap_on,0,*(addresses[1:]+[0]*(4-len(addresses))))
  r=subprocess.run([str(oracle)],input=payload,capture_output=True,pass_fds=(fd,),timeout=5)
  a.require(b.fp(os.fstat(fd))==b.fp(root.stat()),'insert_directory_changed')
 finally:os.close(fd)
 w.check();a.require(r.returncode==0 and not r.stderr,'insert_native_execution')
 rows=[];pos=0
 for ad in addresses:
  a.require(len(r.stdout)-pos>=148,'insert_trace_short');v=struct.unpack_from('<29I',r.stdout,pos);row=dict(zip(FIELDS,v));name=r.stdout[pos+116:pos+148];a.require(b'\0' in name,'insert_filename_trace');row['filename']=name.split(b'\0',1)[0].decode('ascii');pos+=148;data=r.stdout[pos:pos+v[1]];a.require(len(data)==v[1] and len(data)<=length,'insert_payload_size');pos+=v[1];rows.append((row,data))
 a.require(pos==len(r.stdout),'insert_trace_trailing');return rows

def compare(oracle,root,addresses,length,**kw):
 rows=native(oracle,root,addresses,length,**kw);root=b.safe(Path(root));cache={};alloc=opens=reads=locks=formats=0;head=None
 mode=kw.get('mode',1);re=kw.get('read_error',0);oe=kw.get('open_error',0);ron=kw.get('read_error_on',0);oon=kw.get('open_error_on',0);fo=kw.get('format_override',0)
 for i,(ad,(r,data)) in enumerate(zip(addresses,rows)):
  ar=ad>>30;off=ad&0x3fffffff;status=0;expected=b'';didread=False;gate=old.range_model(ad,length)
  if not gate['valid']:status=10
  elif length:
   locks+=1
   if ar not in cache:
    formats+=1
    if fo>=780:status=10
    else:
     opens+=1
     err=5 if not mode else oe if (not oon or oon==opens) else 0
     if not err and not (root/f'data.{ar:03d}').exists():err=2
     if err:status=2 if err==2 else 24 if err==32 else 8
     else:cache[ar]=alloc;alloc+=1
   if status==0:
    didread=True;reads+=1;head=cache[ar]
    if re and (not ron or ron==reads):status=0 if re==38 else 8
    else:
     p=b.safe(root/f'data.{ar:03d}',True);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
     try:expected=os.pread(fd,length,off)
     finally:os.close(fd)
  e={'status':status,'actual_bytes':len(expected),'create_calls':opens,'constructor_calls':alloc,'read_calls':reads,'format_calls':formats,'locks':locks,'unlocks':locks,'reference0_after':len(cache),'new_reference_after':1 if didread else 0,'new_reference_during_read':2 if didread else 0,'list_head':head if head is not None else 0xffffffff,'entry0_hash':0}
  a.require(all(r[k]==v for k,v in e.items()),'insert_original_model_parity');a.require(data==expected,'insert_payload_parity')
 return rows

def require_exact(rows,length):
 a.require(all(r['status']==0 and r['actual_bytes']==length and len(data)==length for r,data in rows),'insert_exact_read_required')
