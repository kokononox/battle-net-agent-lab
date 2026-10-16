"""Bounded Agent 9824 V8 bind experiment, not a game-installation writer.

Index value qwords are opaque; location/span interpretation is experiment policy,
not proof of the complete Agent read-path semantics. V7 remains CascLib-only.
"""
import struct,subprocess
from pathlib import Path
import synthetic_casc_format as fmt
import patch_audit as a
import source_binding as b
LIMIT=1024**2

def align(v,n):return (v+n-1)&-n

def record(ekey,qword0,qword1):
 a.key(ekey);a.require(all(type(x)is int and 0<=x<1<<64 for x in (qword0,qword1)),'bind_qword_bounds')
 return bytes.fromhex(ekey)+struct.pack('<QQ',qword0,qword1)

def make_index(rows,bucket):
 a.require(type(bucket)is int and 0<=bucket<16 and len(rows)<=1024,'bind_builder_bounds')
 rows=sorted(rows);a.require(all(type(r)is bytes and len(r)==32 for r in rows),'bind_record_width')
 a.require(len({r[:16] for r in rows})==len(rows),'bind_duplicate_key')
 header=struct.pack('<HBBBBBBQ',8,bucket,0,8,8,16,30,0x4000000000)
 high=low=0
 for r in rows:high,low=fmt.hashlittle2(r,high,low)
 raw=struct.pack('<II',16,fmt.hashlittle2(header)[0])+header+bytes(8)+struct.pack('<II',len(rows)*32,high)+b''.join(rows)
 tail=align(len(raw),4096)
 return raw+bytes(align(tail+0x7800,0x20000)-len(raw))

def strict_read(raw,bucket):
 """Deliberately narrower than Agent: only our sorted primary-only V8 profile."""
 a.require(type(raw)is bytes and 0<len(raw)<=LIMIT,'bind_input_size')
 a.require(type(bucket)is int and 0<=bucket<16,'bind_bucket')
 a.require(len(raw)>=40,'bind_short_index');n,h=struct.unpack_from('<II',raw)
 a.require(n==16 and fmt.hashlittle2(raw[8:24])[0]==h,'bind_header_guard')
 expected=struct.pack('<HBBBBBBQ',8,bucket,0,8,8,16,30,0x4000000000)
 a.require(raw[8:24]==expected and raw[24:32]==bytes(8),'bind_strict_header_profile')
 size,check=struct.unpack_from('<II',raw,32);a.require(size%32==0 and size//32<=1024 and 40+size<=len(raw),'bind_primary_bounds')
 rows=[raw[i:i+32] for i in range(40,40+size,32)];high=low=0
 for r in rows:high,low=fmt.hashlittle2(r,high,low)
 a.require(high==check,'bind_primary_checksum');keys=[r[:16] for r in rows]
 a.require(keys==sorted(keys) and len(set(keys))==len(keys),'bind_sorted_unique')
 tail=align(40+size,4096);a.require(len(raw)==align(tail+0x7800,0x20000),'bind_strict_file_size')
 a.require(raw[40+size:]==bytes(len(raw)-40-size),'bind_strict_zero_padding_and_empty_tail')
 return rows

def admissible(raw,bucket,map_error=0,query=None):
 a.require(type(raw)is bytes and 0<len(raw)<=LIMIT,'bind_input_size')
 a.require(type(bucket)is int and 0<=bucket<16,'bind_bucket')
 a.require(type(map_error)is int and 0<=map_error<1<<32,'bind_map_error')
 if query is not None:a.key(query)
 if len(raw)>=8:
  n=struct.unpack_from('<I',raw)[0];a.require(n<=LIMIT,'bind_unsafe_header_size');at=align(n+8,16)
  if at<len(raw) and len(raw)-at>=4:a.require(struct.unpack_from('<I',raw,at)[0]<=LIMIT,'bind_unsafe_primary_size')

def model(raw,bucket,map_error=0,query=None):
 """Nonthrowing parser prediction; not a safe general-purpose untrusted parser."""
 admissible(raw,bucket,map_error,query)
 out={'status':0,'records':0,'tail_pages':0,'max_low':0,'max_high':0,'begin':0,'end':0,'cleanup_zero':1,'map_calls':1,'unmap_calls':2,'log_calls':0,'length_calls':2,'selected':None}
 def bad(code=9):
  out.update(status=code,records=0,tail_pages=0,max_low=0,max_high=0,unmap_calls=3);out['log_calls']+=1;return out
 if map_error:return bad(map_error)
 if len(raw)<8:return bad()
 n,h=struct.unpack_from('<II',raw)
 if n+8>len(raw):return bad()
 if fmt.hashlittle2(raw[8:8+n])[0]!=h:return bad()
 if n<16:return bad(5)
 ver,buck,flags,sw,ow,kw,bits,maxoff=struct.unpack_from('<HBBBBBBQ',raw,8)
 if buck!=bucket:return bad()
 if ver<8 or (sw,ow,kw)!=(8,8,16):return bad(5)
 if flags:out['log_calls']+=1
 at=align(n+8,16)
 if at>=len(raw) or len(raw)-at<8:return bad()
 size,check=struct.unpack_from('<II',raw,at)
 if size+8>len(raw)-at:return bad()
 rows=[raw[i:i+32] for i in range(at+8,at+8+(size//32)*32,32)];high=low=0
 for r in rows:high,low=fmt.hashlittle2(r,high,low)
 if high!=check:return bad()
 tail=align(at+8+size,4096)
 if tail>=len(raw) or len(raw)-tail<0x7800:return bad()
 pages=(len(raw)-tail)//1024;done=False
 for p in range(pages):
  for j in range(25):
   slot=tail+p*1024+j*40;check=struct.unpack_from('<I',raw,slot)[0]
   if not check:done=True;break
   if fmt.hashlittle2(raw[slot+4:slot+37])[0]|0x80000000!=check:return bad()
  if done:break
 out.update(records=len(rows),tail_pages=pages,max_low=maxoff&0xffffffff,max_high=maxoff>>32)
 if query is not None:
  # Match the actual binary-search insertion/range algorithm, including duplicates.
  key=bytes.fromhex(query);lo=0;hi=len(rows)
  while lo!=hi:
   mid=(lo+hi)//2
   if rows[mid][:16]==key:lo=mid;break
   if key<rows[mid][:16]:hi=mid
   else:lo=mid+1
  if lo!=hi:
   hi=lo+1
   while lo and rows[lo-1][:16]==key:lo-=1
   while hi<len(rows) and rows[hi][:16]==key:hi+=1
  out.update(begin=lo,end=hi,selected=rows[lo].hex() if lo<hi else None)
 return out

def native(binary,raw,bucket,map_error=0,query=None):
 admissible(raw,bucket,map_error,query);binary=b.safe(Path(binary),True)
 payload=struct.pack('<4I',len(raw),bucket,map_error,int(query is not None))+(bytes.fromhex(query) if query is not None else bytes(16))+raw
 proc=subprocess.run([str(binary)],input=payload,capture_output=True,timeout=8)
 a.require(proc.returncode==0 and len(proc.stdout)==96 and not proc.stderr,'bind_native_execution')
 values=struct.unpack('<16I',proc.stdout[:64]);names=('status','records','tail_pages','max_low','max_high','begin','end','cleanup_zero','map_calls','unmap_calls','log_calls','length_calls')
 out=dict(zip(names,values));a.require(values[12:]==(0,0,0,0) and out['cleanup_zero']==1,'bind_native_canaries')
 out['selected']=proc.stdout[64:].hex() if out['begin']<out['end'] else None;return out

def compare(binary,raw,bucket,map_error=0,query=None):
 expected=model(raw,bucket,map_error,query);actual=native(binary,raw,bucket,map_error,query);a.require(actual==expected,'bind_native_model_parity');return actual

def real_experiment(prior,out,oracle):
 """New V8-only derived index set; prior V7 owned store is read-only."""
 import json
 import retail_update_cycle as cycle
 import retail_storage_poc as old
 import archive_prefix_poc as prefix
 import synthetic_casc_store as fs
 prior=b.safe(Path(prior));out=old.safe_new(Path(out));a.require(prior not in out.parents,'bind_output_in_prior_store')
 watch=b.Watch()
 for p in sorted(prior.iterdir()):watch.file(p)
 with cycle.locked(prior) as locked:
  view=cycle.inspect(locked);a.require(view['updated'] and view['journal']['state']=='committed','bind_prior_completed_cycle')
 data=view['data'];seed=view['seed'];rows={i:[] for i in range(16)}
 for bucket,key in enumerate(prefix.keys(seed,0,1024)):rows[bucket].append(record(key.hex(),bucket*30,30))
 rows[fmt.bucket(cycle.SOURCE)].append(record(cycle.SOURCE,480,188));rows[fmt.bucket(cycle.TARGET)].append(record(cycle.TARGET,668,188))
 built={i:make_index(rows[i],i) for i in range(16)};results=[]
 for i,raw in built.items():
  strict_read(raw,i);proof=compare(oracle,raw,i);a.require(proof['status']==0,'bind_real_native_rejected');results.append({'bucket':i,'index_sha256':a.sha256(raw),'bytes':len(raw),'records':proof['records'],'native_status':proof['status']})
 objects=[]
 for key,ckey,offset in ((cycle.SOURCE,cycle.SOURCE_CK,480),(cycle.TARGET,old.CK,668)):
  bucket=fmt.bucket(key);proof=compare(oracle,built[bucket],bucket,query=key);a.require(proof['end']-proof['begin']==1,'bind_real_unique_lookup')
  selected=bytes.fromhex(proof['selected']);q0,q1=struct.unpack_from('<QQ',selected,16);a.require((q0,q1)==(offset,188),'bind_real_opaque_qword_roundtrip')
  # Interpretation below is our explicit fixture policy, not execution of Agent span I/O.
  decoded,spanproof=fmt.read_span(data[q0:q0+q1],key,33940,ckey,0,q0)
  objects.append({'ekey':key,'ckey':ckey,'source_ckey_is_derived_not_independent':key==cycle.SOURCE,'native_full_key_search_found':True,'qword0':q0,'qword1':q1,'qword_interpretation':'fixture policy: archive 0 absolute offset and span length; full Agent value read-path not proven','span_readback':'independent Python strict full EKey, span checksums, BLTE and decoded CKey','decoded_bytes':len(decoded),'decoded_sha256':a.sha256(decoded)})
 oldbucket=fmt.bucket(cycle.TARGET);v7=watch.read(prior/cycle.idx(oldbucket,2),4096);v7proof=compare(oracle,v7,oldbucket);a.require(v7proof['status']==5,'bind_v7_expected_rejection')
 out.mkdir();fs.write_new(out/'V8-RESEARCH-ONLY.json',old.canonical({'format':'agent-bind-v8-owned-experiment-1','not_installation':True,'qword_semantics':'fixture_policy_only','original_store_mutated':False}));fs.write_new(out/'data.000',data)
 for i,raw in built.items():fs.write_new(out/f'{i:02x}00000001.idx',raw)
 fs.sync_dir(out);watch.check()
 return {'format':'real-retail-v8-bind-experiment-1','all_16_indexes_accepted_by_original_inner_bind':True,'total_primary_records':sum(x['records'] for x in results),'indexes':results,'objects':objects,'old_v7_native_status':v7proof['status'],'v7_was_casclib_only_not_agent_bind_proof':True,'data_bytes':len(data),'data_sha256':a.sha256(data),'prior_owned_store_identities_unchanged':True,'v8_indexes_written_only_in_new_owned_experiment':True,'windows_agent_executed':False,'windows_mapping_and_io_executed':False,'outer_seh_retry_executed':False,'full_agent_qword_value_semantics_proven':False,'full_agent_object_readpath_executed':False,'installation_ready':False,'network_requests':0}
