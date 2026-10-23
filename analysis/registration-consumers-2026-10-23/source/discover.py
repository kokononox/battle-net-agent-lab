"""Syntactic RIP index for a specific helper anchor, not generic code discovery."""
from pathlib import Path
import json,hashlib,struct,bisect
import numpy as np,pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
D=Path(__file__).resolve().parents[1];b=Path('/data/wlab-inputs/wow_loader.dll').read_bytes();PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';assert hashlib.sha256(b).hexdigest()==PIN
p=pefile.PE(data=b);base=p.OPTIONAL_HEADER.ImageBase;lo,hi=0x20d2d18,0x20d2d20
es=[e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION];starts=[e.BeginAddress for e in es]
def owner(a):
 i=bisect.bisect_right(starts,a)-1
 return [es[i].BeginAddress,es[i].EndAddress] if i>=0 and a<es[i].EndAddress else None
initial_node=struct.unpack('<Q',p.get_data(lo,8))[0]-base
targets=[('head_slot',lo,hi),('initial_node_fields',initial_node,initial_node+16)]
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;out={}
for s in p.sections:
 if not s.Characteristics&0x20000000:continue
 raw=s.get_data()[:min(s.SizeOfRawData,s.Misc_VirtualSize)];n=len(raw);pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=raw,strides=(1,));arr=np.frombuffer(raw,dtype=np.uint8);mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
 for tail in [0,1,2,4,8]:
  dest=s.VirtualAddress+pos+4+tail+disp
  mask=np.zeros(n-3,dtype=bool)
  for _,a,z in targets:mask|=(dest>=a)&(dest<z)
  for q0 in np.flatnonzero(mod&mask):
   q=int(q0)
   for start in range(max(0,q-11),q-1):
    i=next(md.disasm(raw[start:start+15],s.VirtualAddress+start,count=1),None)
    if i is None or i.disp_size!=4 or start+i.disp_offset!=q or start+i.size!=q+4+tail:continue
    for op in i.operands:
     if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
      t=i.address+i.size+op.mem.disp
      if any(a<=t<z for _,a,z in targets):out[(i.address,i.bytes.hex())]={'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'target_rva':t,'disp_offset':i.disp_offset,'function':owner(i.address)}
rel=[]
for block in p.DIRECTORY_ENTRY_BASERELOC:
 for e in block.entries:
  if e.type==10:
   v=struct.unpack('<Q',p.get_data(e.rva,8))[0]
   if any(a<=v-base<z for _,a,z in targets):rel.append({'slot_rva':e.rva,'target_rva':v-base})
head=struct.unpack('<Q',p.get_data(lo,8))[0]-base
node={'rva':head,'first_qword':struct.unpack('<Q',p.get_data(head,8))[0],'second_qword':struct.unpack('<Q',p.get_data(head+8,8))[0]}
r={'sha256':PIN,'target_ranges':targets,'head_disk_qword':head+base,'initial_node_disk_fields':node,'syntactic_candidates':sorted(out.values(),key=lambda c:c['rva']),'relocation_backed_pointers':rel,'claims':{'runtime_consumer_identified':False,'eid_consumer_identified':False}}
(D/'reports/discovery.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
