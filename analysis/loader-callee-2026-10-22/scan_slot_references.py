"""Byte-level RIP-relative candidates, NOT proven reachable instructions or complete xrefs."""
from pathlib import Path
import argparse,sys,os,json,hashlib
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import numpy as np,pefile,capstone
from capstone.x86_const import X86_REG_RIP
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/wow_loader.dll'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();b=a.input.read_bytes();assert hashlib.sha256(b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
slots=[0x20a0400,0x20a0798];found={};checks=0
for sec in pe.sections:
 if not sec.Characteristics&0x20000000:continue
 data=sec.get_data();sv=sec.VirtualAddress
 for alignment in range(4):
  n=(len(data)-alignment)//4;vals=np.frombuffer(data,dtype='<i4',count=n,offset=alignment);ends=np.arange(n,dtype=np.int64)*4+sv+alignment+4
  for tail in (0,1,2,4):
   for slot in slots:
    indices=np.flatnonzero(vals==slot-ends-tail)
    for index in indices:
     disp_r=sv+alignment+int(index)*4;expected_end=disp_r+4+tail
     for start in range(max(sv,disp_r-10),disp_r):
      i=next(md.disasm(pe.get_data(start,15),base+start,count=1),None)
      if not i or i.address+i.size-base!=expected_end or i.disp_size!=4 or start+i.disp_offset!=disp_r:continue
      for op in i.operands:
       if op.type==capstone.CS_OP_MEM and op.mem.base==X86_REG_RIP and start+i.size+op.mem.disp==slot:
        checks+=1;found[(start,slot)]={'candidate_rva':hex(start),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'slot_rva':hex(slot),'operand_access_flags':op.access,'operand_size_bytes':op.size,'proven_reachable':False,'unwind_containing_ranges':[{'begin':hex(e.struct.BeginAddress),'end':hex(e.struct.EndAddress)} for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=start<e.struct.EndAddress]}
result={'scope':'Candidates from executable raw sections, decoded with Capstone. Includes alternate instruction starts inside prefixes/operands. No reachability proof. Only direct RIP-relative addressing with a four-byte displacement and trailing immediate length 0/1/2/4 searched. Register-indirect, computed, bulk writes and runtime code are not covered.','references':[found[k] for k in sorted(found)],'candidates':len(found),'source_sha256':hashlib.sha256(b).hexdigest()}
(a.out/'slot-reference-candidates.json').write_text(json.dumps(result,indent=2)+'\n');print('candidate count',len(found))
for x in result['references']: print(x['candidate_rva'],x['mnemonic'],x['operands'],'slot',x['slot_rva'],'access',x['operand_access_flags'])
