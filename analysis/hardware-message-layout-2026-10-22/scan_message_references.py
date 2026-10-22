"""Byte-level RIP-relative candidates, NOT proven reachable instructions or complete xrefs."""
from pathlib import Path
import argparse,sys,os,json,hashlib
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import numpy as np,pefile,capstone
from capstone.x86_const import X86_REG_RIP
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();b=a.input.read_bytes();assert hashlib.sha256(b).hexdigest()=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';pe=pefile.PE(data=b,fast_load=True);pe.parse_data_directories(directories=[3]);base=pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
targets=[0x47c7dc0,0x47cebb0,0x4855470,0x4856510,0x415a938,0x415b658,0x42a4f50,0x42a49f8,0x42a3d78];found={};checks=0;scanned=[]
for sec in pe.sections:
 if not sec.Characteristics&0x20000000:continue
 data=sec.get_data();sv=sec.VirtualAddress;scanned.append({'name':sec.Name.decode().rstrip('\0'),'rva':hex(sv),'raw_size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 for alignment in range(4):
  n=(len(data)-alignment)//4;vals=np.frombuffer(data,dtype='<i4',count=n,offset=alignment);ends=np.arange(n,dtype=np.int64)*4+sv+alignment+4
  for tail in (0,1,2,4):
   for target in targets:
    indices=np.flatnonzero(vals==target-ends-tail)
    for index in indices:
     disp_r=sv+alignment+int(index)*4;expected_end=disp_r+4+tail
     for start in range(max(sv,disp_r-10),disp_r):
      i=next(md.disasm(pe.get_data(start,15),base+start,count=1),None)
      if not i or i.address+i.size-base!=expected_end or i.disp_size!=4 or start+i.disp_offset!=disp_r:continue
      for op in i.operands:
       if op.type==capstone.CS_OP_MEM and op.mem.base==X86_REG_RIP and start+i.size+op.mem.disp==target:
        checks+=1;found[(start,target)]={'candidate_rva':hex(start),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'target_rva':hex(target),'operand_access_flags':op.access,'operand_size_bytes':op.size,'proven_reachable':False,'unwind_containing_ranges':[{'begin':hex(e.struct.BeginAddress),'end':hex(e.struct.EndAddress)} for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=start<e.struct.EndAddress]}
result={'target_rvas':[hex(x) for x in targets],'executable_sections_scanned':scanned,'scope':'Candidates from executable raw sections, decoded with Capstone. Includes alternate instruction starts inside prefixes/operands. No reachability proof. Only direct RIP-relative addressing with a four-byte displacement and trailing immediate length 0/1/2/4 searched. Register-indirect, computed, bulk writes and runtime code are not covered.','references':[found[k] for k in sorted(found)],'candidates':len(found),'source_sha256':hashlib.sha256(b).hexdigest()}
(a.out/'message-reference-candidates.json').write_text(json.dumps(result,indent=2)+'\n');print('candidate count',len(found))
for x in result['references']: print(x['candidate_rva'],x['mnemonic'],x['operands'],'target',x['target_rva'],'access',x['operand_access_flags'])
