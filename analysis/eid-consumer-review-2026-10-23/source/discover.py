"""Discovery only: syntactic candidates are NOT validated code or consumers."""
from pathlib import Path
import hashlib,json,struct,bisect
import numpy as np,pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
D=Path(__file__).resolve().parents[1];b=Path('/data/wlab-inputs/wow_loader.dll').read_bytes();assert hashlib.sha256(b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
p=pefile.PE(data=b);base=p.OPTIONAL_HEADER.ImageBase
sections={s.Name.rstrip(b'\0').decode():s for s in p.sections};targets=[(name,sections[name].VirtualAddress,sections[name].VirtualAddress+sections[name].Misc_VirtualSize) for name in ['.eid','.eidsig']]
es=[e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION];starts=[e.BeginAddress for e in es]
def owner(a):
 i=bisect.bisect_right(starts,a)-1
 return [es[i].BeginAddress,es[i].EndAddress] if i>=0 and a<es[i].EndAddress else None
def which(a):return next((name for name,lo,hi in targets if lo<=a<hi),None)
relocs=[]
for block in getattr(p,'DIRECTORY_ENTRY_BASERELOC',[]):
 for e in block.entries:
  if e.type!=10:continue
  raw=p.get_data(e.rva,8)
  if len(raw)==8:
   value=struct.unpack('<Q',raw)[0];name=which(value-base)
   if name:relocs.append({'slot_rva':e.rva,'target_rva':value-base,'section':name,'containing_function':owner(e.rva)})
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
candidates={};constants=[]
needlevals=[('eid_rva',0x2270000),('eid_virtual_size',0x5d0000),('eidsig_rva',0x2210000),('magic_EIDO',0x4f444945),('magic_LON0b',0x0b4e4f4c)]
for s in p.sections:
 if not s.Characteristics&0x20000000:continue
 data=s.get_data()[:min(s.SizeOfRawData,s.Misc_VirtualSize)];n=len(data);pos=np.arange(n-3,dtype=np.int64)
 disp=np.ndarray((n-3,),dtype='<i4',buffer=data,strides=(1,))
 # A RIP displacement must follow ModRM with mod=00,rm=101. Decode all possible starts within the x86 15-byte bound.
 modrm=np.frombuffer(data,dtype=np.uint8);ok=np.zeros(n-3,dtype=bool);ok[1:]=(modrm[:n-4]&0xc7)==5
 for tail in [0,1,2,4,8]:
  dest=s.VirtualAddress+pos+4+tail+disp
  idx=np.flatnonzero(ok & (((dest>=targets[0][1])&(dest<targets[0][2]))|((dest>=targets[1][1])&(dest<targets[1][2]))))
  for q0 in idx:
   q=int(q0)
   for start in range(max(0,q-11),q-1):
    ins=next(md.disasm(data[start:start+15],s.VirtualAddress+start,count=1),None)
    if ins is None or ins.disp_size!=4 or start+ins.disp_offset!=q or start+ins.size!=q+4+tail:continue
    for op in ins.operands:
     if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
      target=ins.address+ins.size+op.mem.disp;name=which(target)
      if name:
       key=(ins.address,bytes(ins.bytes));candidates[key]={'rva':ins.address,'bytes':ins.bytes.hex(),'asm':ins.mnemonic+' '+ins.op_str,'disp_offset':ins.disp_offset,'immediate_tail_bytes':ins.size-ins.disp_offset-4,'target_rva':target,'target_section':name,'containing_function':owner(ins.address)}
 for label,value in needlevals:
  needle=struct.pack('<I',value);at=0
  while (at:=data.find(needle,at))>=0:
   hits=[]
   for start in range(max(0,at-11),at):
    ins=next(md.disasm(data[start:start+15],s.VirtualAddress+start,count=1),None)
    if ins and ins.imm_size==4 and start+ins.imm_offset==at and any(op.type==X86_OP_IMM and (op.imm&0xffffffff)==value for op in ins.operands):
     hits.append({'rva':ins.address,'bytes':ins.bytes.hex(),'asm':ins.mnemonic+' '+ins.op_str,'containing_function':owner(ins.address)})
   constants.append({'label':label,'value':value,'literal_rva':s.VirtualAddress+at,'syntactic_instructions':hits});at+=1
names=[]
for value in [b'.eid\0',b'.eidsig\0',b'EIDOLON','.eid'.encode('utf-16-le')+b'\0\0']:
 offsets=[];at=0
 while (at:=b.find(value,at))>=0:offsets.append(at);at+=1
 names.append({'needle_hex':value.hex(),'file_offsets':offsets})
r={'input_sha256':hashlib.sha256(b).hexdigest(),'target_sections':targets,'relocation_backed_pointers':relocs,'rip_syntactic_candidates':sorted(candidates.values(),key=lambda x:x['rva']),'immediate_literal_candidates':constants,'literal_names':names,'claims':{'candidate_instructions_validated_as_reachable':False,'eid_consumer_identified':False,'decryption_identified':False}}
(D/'reports/discovery.json').write_text(json.dumps(r,indent=2)+'\n')
print('Relocation-backed pointers',len(relocs),relocs[:12]);print('RIP syntactic candidates',len(candidates),'functions',len({tuple(x['containing_function']) for x in candidates.values() if x['containing_function']}));print('Immediate literals',len(constants));print('Literal names',names)
print('Sample RIP candidates',json.dumps(list(candidates.values())[:8]));print('Immediate candidates',json.dumps(constants[:15]))
