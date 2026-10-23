from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import numpy as np,json,hashlib,struct
root=Path('/data/wlab-interrupt-slot-review');p=PE(Path('/data/wlab-inputs/wow_loader.dll'));digest=hashlib.sha256(p.b).hexdigest();assert digest=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;slot=0x219bdc8;candidates={};scanned=0
# Exact RIP-relative displacement candidates. Scan raw executable sections in small chunks.
# Include displacement followed by 0,1,2,4,8 immediate bytes, then independently decode each hit.
for name,vs,va,rs,ro in p.sections:
 # Get section characteristics from the PE section table rather than infer from name.
 o=struct.unpack_from('<I',p.b,0x3c)[0];opt=o+24;sz=struct.unpack_from('<H',p.b,o+20)[0]
 idx=[x[0] for x in p.sections].index(name);char=struct.unpack_from('<I',p.b,opt+sz+idx*40+36)[0]
 if not char&0x20000000:continue
 scanned+=rs
 raw=p.b[ro:ro+rs]
 for offset in range(0,rs-3,1<<20):
  count=min(1<<20,rs-3-offset);vals=np.ndarray((count,),dtype='<i4',buffer=raw,offset=offset,strides=(1,));positions=np.arange(count,dtype=np.int64)+va+offset
  for tail in [0,1,2,4,8]:
   hits=np.flatnonzero(vals.astype(np.int64)+positions+4+tail==slot)
   for k in hits:
    disp_rva=va+offset+int(k)
    for back in range(1,12):
     start=disp_rva-back
     if start<va:continue
     i=next(m.disasm(p.read(start,15),start,count=1),None)
     if not i or i.disp_offset!=back or i.disp_size!=4:continue
     for op in i.operands:
      if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP and i.address+i.size+op.mem.disp==slot:
       candidates[start]={'rva':start,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'access':('read' if op.access&CS_AC_READ else '')+('write' if op.access&CS_AC_WRITE else '') or 'unknown','instruction_boundary_proven':False,'reachable_writer_proven':False}
# Mark only the already-linked thunk's exact known entry boundary, not raw scan candidates generally.
if 0x1f4dc80 in candidates:candidates[0x1f4dc80]['instruction_boundary_proven']=True
s,z=p.dirs[3];table=[struct.unpack('<III',p.read(a,12)) for a in range(s,s+z,12)]
r={'sha256':digest,'interrupt_stub':{'rva':0x74a8e0,'first_bytes':p.read(0x74a8e0,16).hex(),'instruction':'int 0x2c','runtime_function_matches':[list(t) for t in table if t[0]<=0x74a8e0<t[1]],'runtime_interrupt_disposition':'unknown'},'wrapper':{'begin':0xdeea10,'bytes_through_call_and_trap':p.read(0xdeea10,26).hex(),'call_site':0xdeea24,'callee':0xdeea24+5+p.u(0xdeea25,'<i'),'runtime_function_matches':[list(t) for t in table if t[0]<=0xdeea10<t[1]]},'slot':{'rva':slot,**p.loc(slot,8),'runtime_value_known':False},'slot_reference_scan':{'executable_raw_bytes':scanned,'tails':[0,1,2,4,8],'candidates':[candidates[k] for k in sorted(candidates)],'scope':'Raw RIP-relative references only. Does not cover computed addresses, register-based writes, indirect initialization, runtime-generated code, exception transfers or all instruction starts. No writer is proven solely by decoding.'},'claims':{'decryptor_recovered':False,'slot_writer_proven':False,'key_recovered':False,'hardware_send_proven':False}}
(root/'evidence.json').write_text(json.dumps(r,indent=2));print('stub',r['interrupt_stub']);print('scan bytes',scanned,'candidates',r['slot_reference_scan']['candidates'])
