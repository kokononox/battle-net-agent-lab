"""Bounded original Agent archive-read path, with explicit open/OS adapters.

Original selection/range/masking/read/error functions execute unchanged. The
open/cache manager is NOT executed; caller supplies one read-only descriptor.
ReadFile is adapted to actual Linux pread64, not Windows I/O. Normal frames,
release and logging are adapters; unmodelled alignment/membership paths trap.
"""
import os,struct,subprocess
from pathlib import Path
import agent_static_audit as identity
import agent_span_reader as span_reader
import patch_audit as a
import source_binding as b
import synthetic_casc_format as fmt
MASK=(1<<64)-1
FIELDS=('status','actual_bytes','open_calls','archive','read_calls','releases','open_flags','offset_low','offset_high','requested_bytes','descriptor','lower_error_logs')
def inputs(address,length,mode=0,read_error=0,open_error=0):
 for value,maximum,label in ((address,MASK,'address'),(length,4096,'length'),(mode,1,'mode'),(read_error,0xffffffff,'read_error'),(open_error,0xffffffff,'open_error')):
  a.require(type(value)is int and 0<=value<=maximum,'io_'+label+'_profile')
def range_model(address,length):
 inputs(address,length)
 # Preserve the original low-DWORD truncation after the u64 shift. This is a
 # primitive model, NOT our stricter admission policy for a research storage.
 ar=(address>>30)&0xffffffff;last=(((address+length-1)&MASK)>>30)&0xffffffff if length else ar
 return {'valid':ar<1023 and ar==last,'archive':ar}
def oracle_identity(oracle):
 oracle=b.safe(Path(oracle),True);w=b.Watch();r=b.json_object(w.read(oracle.parent/'BUILD-RECEIPT.json',65536))
 a.require(r.get('format')=='agent-archive-io-build-1' and r.get('agent_sha256')==identity.AGENT_SHA256 and r.get('original_bytes_verified_in_elf') is True and r.get('no_rwx') is True and r.get('nx_stack') is True and r.get('original_open_manager_executed') is False and r.get('windows_io_executed') is False,'io_oracle_receipt')
 a.require(a.sha256(w.read(oracle,2*1024**2))==r.get('binary_sha256'),'io_oracle_digest');w.check();return oracle

def native(oracle,path,address,length,mode=0,read_error=0,open_error=0):
 """Primitive observation, including short successful reads. No full-object claim.

One safe regular file only, no scan, network, writes or automatic fallback.
Local build receipt is an integrity check, not signed/adversarial trust.
"""
 inputs(address,length,mode,read_error,open_error);oracle=oracle_identity(oracle);w=b.Watch();path=w.file(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a.require(b.fp(os.fstat(fd))==w.files[path],'io_descriptor_identity')
  proc=subprocess.run([str(oracle)],input=struct.pack('<Q5I',address,length,mode,read_error,open_error,fd),capture_output=True,pass_fds=(fd,),timeout=5)
  a.require(b.fp(os.fstat(fd))==w.files[path],'io_descriptor_changed')
 finally:os.close(fd)
 w.check();a.require(proc.returncode==0 and not proc.stderr and len(proc.stdout)>=48,'io_native_execution')
 result=dict(zip(FIELDS,struct.unpack('<12I',proc.stdout[:48])));payload=proc.stdout[48:]
 a.require(len(payload)==result['actual_bytes'] and len(payload)<=length,'io_output_length');return result,payload

def compare(oracle,path,address,length,mode=0,read_error=0,open_error=0):
 """Compare original range/routing/error semantics with an independent model.
 Actual bytes are independently pread by Python from the same watched file.
 """
 inputs(address,length,mode,read_error,open_error);w=b.Watch();p=w.file(path)
 got,data=native(oracle,p,address,length,mode,read_error,open_error);expected={n:0 for n in FIELDS};gate=range_model(address,length)
 if not gate['valid']:expected['status']=10
 elif length:
  expected.update(open_calls=1,archive=gate['archive'],open_flags=4 if mode else 1)
  if open_error:expected['status']=open_error
  else:
   offset=address&0x3fffffff
   expected.update(read_calls=1,releases=1,offset_low=offset,requested_bytes=length,descriptor=got['descriptor'])
   if read_error not in (0,38):expected.update(status=8,lower_error_logs=1)
   elif not read_error:
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
     a.require(b.fp(os.fstat(fd))==w.files[p],'io_compare_descriptor_identity');independent=os.pread(fd,length,offset)
    finally:os.close(fd)
    a.require(data==independent,'io_actual_bytes_parity');expected['actual_bytes']=len(independent)
 a.require(got==expected,'io_original_model_parity');w.check();return got,data

def read_numbered(oracle,span_oracle,files,address,size,ekey,decoded_size,ckey):
 a.key(ekey);a.key(ckey)
 a.require(type(address)is int and 0<=address<1023*(1<<30),'io_reader_address_profile')
 a.require(type(size)is int and 30<size<=4096,'io_reader_size_profile');ar=address>>30;off=address&0x3fffffff
 a.require(off>=480 and off+size<=1<<30,'io_reader_segment_bounds')
 a.require(type(files)is dict and ar in files,'io_reader_explicit_archive_required');p=Path(files[ar]);a.require(p.name==f'data.{ar:03d}','io_reader_numbered_filename')
 w=b.Watch();raw=w.read(p,2*1024**2)
 got,chunk=compare(oracle,p,address,size)
 a.require(got['status']==0 and got['actual_bytes']==size,'io_reader_exact_read_required')
 a.require(chunk==raw[off:off+size],'io_reader_snapshot_parity')
 parsed=span_reader.compare(span_oracle,chunk[:30],address,size);a.require(parsed['valid'],'io_reader_original_header_rejected')
 rec=bytes.fromhex(parsed['record']);addr,stored_size=struct.unpack_from('<QQ',rec,16)
 a.require(rec[:16].hex()==ekey and addr==address and stored_size==size and rec[32]==0,'io_reader_key_size_flag')
 a.require(parsed['archive']==ar and parsed['payload_offset']==off+30,'io_reader_original_address_mismatch')
 decoded,_=fmt.read_span(chunk,ekey,decoded_size,ckey,ar,off);w.check()
 return {'format':'agent-archive-io-bridge-1','archive':ar,'absolute_address':address,'filename':p.name,'span':size,'payload_offset':off+30,'encoded_sha256':a.sha256(chunk[30:]),'decoded_bytes':len(decoded),'decoded_md5':a.md5(decoded),'original_archive_read_chain_executed':True,'original_header_and_getters_executed':True,'original_open_manager_executed':False,'os_boundary':'ReadFile adapted to Linux pread64 on explicit read-only descriptor','decode_implementation':'independent Python','windows_executed':False,'installation_ready':False}
