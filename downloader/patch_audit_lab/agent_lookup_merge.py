"""Original normal-path V8 lookup/iterator/merge/range experiment, not Agent I/O.

SEH frame and inline-memory destructor helpers are explicit harness boundaries.
No semantic substitute for lookup, collection, event application, merge or range.
"""
import struct,subprocess
from pathlib import Path
import patch_audit as a
import source_binding as b
import synthetic_casc_format as fmt
import agent_bind_contract as bind
import agent_value_range as ranges
MASK=(1<<64)-1

def i32(n):return ((n+(1<<31))&0xffffffff)-(1<<31)
def merge(events):
 grouped={}
 for pos,delta in events:grouped[pos]=i32(grouped.get(pos,0)+delta)
 previous=0;out=[]
 for pos,delta in sorted(grouped.items()):
  current=i32(previous+delta)
  if previous<=0<current:out.append((pos,1))
  elif previous>0>=current:out.append((pos,-1))
  previous=current
 return out

def build_index(primary,tail,bucket):
 """Explicit fixture rows; primary ties preserve caller order."""
 a.require(type(bucket)is int and 0<=bucket<16 and len(primary)<=1024 and len(tail)<=64,'lookup_fixture_limits')
 primary=sorted(primary,key=lambda r:r[:16]);a.require(all(type(r)is bytes and len(r)==32 for r in primary),'lookup_primary_width')
 h=struct.pack('<HBBBBBBQ',8,bucket,0,8,8,16,30,0x4000000000);hi=lo=0
 for r in primary:hi,lo=fmt.hashlittle2(r,hi,lo)
 raw=bytearray(struct.pack('<II',16,fmt.hashlittle2(h)[0])+h+bytes(8)+struct.pack('<II',32*len(primary),hi)+b''.join(primary));at=bind.align(len(raw),4096);raw.extend(bytes(bind.align(at+0x7800,0x20000)-len(raw)))
 for i,(row,flag) in enumerate(tail):
  a.require(type(row)is bytes and len(row)==32 and type(flag)is int and 1<=flag<=7,'lookup_tail_row');payload=row+bytes([flag]);slot=at+(i//25)*1024+(i%25)*40;raw[slot:slot+40]=struct.pack('<I',fmt.hashlittle2(payload)[0]|0x80000000)+payload+bytes(3)
 return bytes(raw)

def admitted(raw,bucket,query,start=0,length=MASK,map_error=0):
 bind.admissible(raw,bucket,map_error,query);a.key(query);ranges.inputs(start,length,0,0)
 a.require(length==MASK or start+length<=MASK,'lookup_nonwrapping_request')
 a.require(len(raw)>=40 and len(raw)<=bind.LIMIT,'lookup_input_length');n,h=struct.unpack_from('<II',raw);a.require(n==16 and fmt.hashlittle2(raw[8:24])[0]==h,'lookup_header_guard')
 header=struct.unpack_from('<HBBBBBBQ',raw,8);a.require(header[:2][0]==8 and 0<=header[1]<16 and header[2:7]==(0,8,8,16,30) and header[7]==0x4000000000 and raw[24:32]==bytes(8),'lookup_header_profile')
 size,check=struct.unpack_from('<II',raw,32);a.require(size%32==0 and size//32<=1024 and 40+size<=len(raw),'lookup_primary_bounds');primary=[raw[at:at+32] for at in range(40,40+size,32)];a.require([r[:16] for r in primary]==sorted(r[:16] for r in primary),'lookup_primary_sorted')
 hi=lo=0
 for r in primary:hi,lo=fmt.hashlittle2(r,hi,lo)
 a.require(hi==check,'lookup_primary_guard');tailat=bind.align(40+size,4096);a.require(len(raw)==bind.align(tailat+0x7800,0x20000) and raw[40+size:tailat]==bytes(tailat-40-size),'lookup_tail_bounds');tail=[]
 # Controlled profile admits at most 64 used slots, then exact zero padding.
 rebuilt=bytearray(len(raw)-tailat)
 for i in range(65):
  at=tailat+(i//25)*1024+(i%25)*40;checksum=struct.unpack_from('<I',raw,at)[0]
  if not checksum:break
  a.require(i<64,'lookup_tail_limit');payload=raw[at+4:at+37];a.require(fmt.hashlittle2(payload)[0]|0x80000000==checksum and raw[at+37:at+40]==bytes(3) and 1<=payload[32]<=7,'lookup_tail_guard_or_flag');tail.append((payload[:32],payload[32]));off=at-tailat;rebuilt[off:off+40]=raw[at:at+40]
 a.require(bytes(rebuilt)==raw[tailat:],'lookup_zero_unused_tail')
 key=bytes.fromhex(query);selected=[r for r in primary if r[:16]==key];selected_tail=[(r,f) for r,f in tail if r[:16]==key]
 a.require(len(selected)+len(selected_tail)<=7,'lookup_inline_capacity_boundary')
 for row in primary+[r for r,f in tail]:
  base,extent=struct.unpack_from('<QQ',row,16);a.require(base+extent<=MASK,'lookup_nonwrapping_value')
 return selected,selected_tail

def predict(raw,bucket,query,start=0,length=MASK,map_error=0):
 primary,tail=admitted(raw,bucket,query,start,length,map_error);bound=bind.model(raw,bucket,map_error,query);answer={'performed':False,'status':None,'range':[0,0],'value':[0,0],'vector_destroy_calls':0,'iterator_destroy_calls':0,'warning_calls':0}
 if bound['status']:return {'bind':bound,'lookup':answer}
 answer.update(performed=True,vector_destroy_calls=1,iterator_destroy_calls=1);valid=False;value=(0,0);events=[]
 def apply(row,flag):
  nonlocal valid,value,events
  incoming=struct.unpack_from('<QQ',row,16)
  if flag in (1,2):valid=True;value=incoming;events=[]
  elif flag==3:valid=False;value=(0,0);events=[]
  elif flag in (4,5):answer['warning_calls']+=1;events=[]
  if flag in (1,4,6,7):
   v=value if flag==4 else incoming;weight=1 if flag!=7 else -0x40000000;events.extend(((v[0],weight),(v[0]+v[1],-weight)))
   if flag==7:events=merge(events)
 if primary:
  apply(primary[0],1 if len(primary)==1 else 2)
  for row in primary[1:]:apply(row,6)
 for row,flag in tail:apply(row,flag)
 events=merge(events)
 if not valid:answer['status']=2;return {'bind':bound,'lookup':answer}
 relative=ranges.model(start,length,*value)
 if not relative['valid']:answer['status']=4;return {'bind':bound,'lookup':answer}
 absolute=value[0]+start;size=relative['length'];answer['range']=[absolute,size]
 if size:
  coverage=0;covered=False
  for pos,delta in events:
   if pos<=absolute:coverage+=delta
   else:covered=coverage>0 and pos>=absolute+size;break
  if not covered:answer['status']=3;return {'bind':bound,'lookup':answer}
 answer.update(status=0,value=list(value));return {'bind':bound,'lookup':answer}

def native(oracle,raw,bucket,query,start=0,length=MASK,map_error=0):
 admitted(raw,bucket,query,start,length,map_error);oracle=b.safe(Path(oracle),True)
 payload=struct.pack('<4I',len(raw),bucket,map_error,1)+bytes.fromhex(query)+struct.pack('<QQ',start,length)+raw;p=subprocess.run([str(oracle)],input=payload,capture_output=True,timeout=6)
 a.require(p.returncode==0 and len(p.stdout)==144 and not p.stderr,'lookup_native_execution');values=struct.unpack_from('<16I',p.stdout);names=('status','records','tail_pages','max_low','max_high','begin','end','cleanup_zero','map_calls','unmap_calls','log_calls','length_calls');bound=dict(zip(names,values));a.require(values[12:]==(0,0,0,0) and bound['cleanup_zero']==1,'lookup_native_canaries');bound['selected']=p.stdout[64:96].hex() if bound['begin']<bound['end'] else None
 status=struct.unpack_from('<I',p.stdout,96)[0];absolute,size=struct.unpack_from('<QQ',p.stdout,100);base,extent=struct.unpack_from('<QQ',p.stdout,116);vector,iterator,warnings=struct.unpack_from('<3I',p.stdout,132);performed=bound['status']==0
 return {'bind':bound,'lookup':{'performed':performed,'status':status if performed else None,'range':[absolute,size],'value':[base,extent],'vector_destroy_calls':vector,'iterator_destroy_calls':iterator,'warning_calls':warnings}}

def compare(oracle,*args,**kw):
 expected=predict(*args,**kw);observed=native(oracle,*args,**kw);a.require(expected==observed,'lookup_original_model_parity');return observed
