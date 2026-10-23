"""Build-pinned backward reference inventory; syntactic matches are NOT callers."""
from pathlib import Path
import hashlib,json,struct,bisect
import numpy as np,pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
D=Path(__file__).resolve().parents[1];b=Path('/data/wlab-inputs/Wow.exe').read_bytes();PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';assert hashlib.sha256(b).hexdigest()==PIN
p=pefile.PE(data=b,fast_load=True);p.parse_data_directories(directories=[3,5]);base=p.OPTIONAL_HEADER.ImageBase
slots={'merge_candidate':0x47cf800,'creator_candidate':0x47cf810,'parse_fallback_candidate':0x47cec38};targets={k:struct.unpack('<Q',p.get_data(s,8))[0]-base for k,s in slots.items()}
assert targets=={'merge_candidate':0x1b14120,'creator_candidate':0x1b11190,'parse_fallback_candidate':0x33068c0}
es=[e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION];starts=[e.BeginAddress for e in es]
def owner(a):
 j=bisect.bisect_right(starts,a)-1
 return [es[j].BeginAddress,es[j].EndAddress] if j>=0 and a<es[j].EndAddress else None
# Geometry comes from prior candidate ClassData/TcParseTable model; not proof of fork ABI.
classbase=slots['creator_candidate']-0x30;table=slots['parse_fallback_candidate']-0x30;prototype=struct.unpack('<Q',p.get_data(classbase,8))[0]-base
assert struct.unpack('<Q',p.get_data(classbase+8,8))[0]-base==table
assert struct.unpack('<Q',p.get_data(table+32,8))[0]-base==classbase
ranges=[('candidate_class_record',classbase,classbase+0x68),('candidate_parse_header',table,table+56),('prototype_first_qword',prototype,prototype+8)]
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;direct={};rip={};chunk=4*1024*1024
for s in p.sections:
 if not s.Characteristics&0x20000000:continue
 raw=s.get_data()[:min(s.SizeOfRawData,s.Misc_VirtualSize)]
 for off in range(0,len(raw),chunk):
  data=raw[off:off+chunk+15];n=len(data);core=min(chunk,len(raw)-off);rva=s.VirtualAddress+off
  if n<5:continue
  # Direct E8/E9 with 32-bit relative displacement at the opcode start.
  pos=np.arange(n-4,dtype=np.int64);disp=np.ndarray((n-4,),dtype='<i4',buffer=data,offset=1,strides=(1,));arr=np.frombuffer(data,dtype=np.uint8);dest=rva+pos+5+disp
  mask=(arr[:n-4]==0xe8)|(arr[:n-4]==0xe9)
  match=np.zeros(n-4,dtype=bool)
  for t in targets.values():match|=dest==t
  for q0 in np.flatnonzero(mask&match&(pos<core+10)):
   q=int(q0)
   for start in range(max(0,q-10),q+1):
    if start>=core:continue
    i=next(md.disasm(data[start:start+15],rva+start,count=1),None)
    if i and i.mnemonic in ['call','jmp'] and i.imm_size==4 and start+i.imm_offset==q+1 and start+i.size==q+5:
     direct[(i.address,i.bytes.hex())]={'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'target_rva':int(dest[q]),'function':owner(i.address)}
  # All candidate RIP disp32 positions; overlap chunk by <=15 bytes.
  pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=data,strides=(1,));mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
  for tail in [0,1,2,4,8]:
   dest=rva+pos+4+tail+disp;match=np.zeros(n-3,dtype=bool)
   for _,lo,hi in ranges:match|=(dest>=lo)&(dest<hi)
   for q0 in np.flatnonzero(mod&match):
    q=int(q0)
    for start in range(max(0,q-11),q-1):
     if start>=core:continue
     i=next(md.disasm(data[start:start+15],rva+start,count=1),None)
     if i is None or i.disp_size!=4 or start+i.disp_offset!=q or start+i.size!=q+4+tail:continue
     for op in i.operands:
      if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
       t=i.address+i.size+op.mem.disp;label=next((name for name,lo,hi in ranges if lo<=t<hi),None)
       if label:rip[(i.address,i.bytes.hex())]={'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'disp_offset':i.disp_offset,'target_rva':t,'target_kind':label,'function':owner(i.address)}
ptrs=[]
for block in p.DIRECTORY_ENTRY_BASERELOC:
 for e in block.entries:
  if e.type!=10:continue
  value=struct.unpack('<Q',p.get_data(e.rva,8))[0];t=value-base
  label=next((k for k,v in targets.items() if v==t),None)
  label=label or next((name for name,lo,hi in ranges if lo<=t<hi),None)
  if label:
   sec=p.get_section_by_rva(e.rva);ptrs.append({'slot_rva':e.rva,'target_rva':t,'target_kind':label,'slot_section':sec.Name.rstrip(b'\0').decode(),'slot_in_executable_section':bool(sec.Characteristics&0x20000000)})
selection={'target':'creator_candidate','reason':'Metadata-pinned creator slot and containing ClassData cycle provide a bounded backward anchor; NOT selected as a confirmed CPU/BIOS collector. Other two code targets indexed for comparison only.','slot_rva':slots['creator_candidate'],'target_rva':targets['creator_candidate']}
result={'sha256':PIN,'image_base':base,'selection':selection,'code_targets':targets,'slot_rvas':slots,'metadata_ranges':ranges,'geometry_assumption':'Prior candidate upstream protobuf ClassData/TcParseTable geometry; fork ABI identity not established.','direct_branch_candidates':sorted(direct.values(),key=lambda x:x['rva']),'rip_metadata_candidates':sorted(rip.values(),key=lambda x:x['rva']),'relocation_backed_references':ptrs,'claims':{'real_caller_identified':False,'hardware_collector_identified':False,'field_population_identified':False,'serialization_or_send_identified':False}}
(D/'reports/discovery.json').write_text(json.dumps(result,indent=2)+'\n');print('SELECTED',selection);print('RANGES',ranges);print('DIRECT',len(direct),'RIP',len(rip),'POINTERS',len(ptrs))
for c in sorted(direct.values(),key=lambda x:x['rva']):print('DIRECT',hex(c['rva']),c['asm'],[hex(v) for v in c['function']] if c['function'] else None)
for c in sorted(rip.values(),key=lambda x:x['rva']):print('RIP',hex(c['rva']),c['asm'],c['target_kind'],[hex(v) for v in c['function']] if c['function'] else None)
