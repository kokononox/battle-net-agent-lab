"""Small unwind-bounded context extraction. API names remain hypotheses."""
from pathlib import Path
import sys,os,json,hashlib,argparse
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile,capstone
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/wow_loader.dll'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
contexts=[]
for start,end in [(0x20062ec,0x2006320),(0x2010390,0x20103c2),(0x2013d9c,0x2013de3)]:
 assert any(e.struct.BeginAddress==start and e.struct.EndAddress==end for e in pe.DIRECTORY_ENTRY_EXCEPTION)
 instructions=[];cursor=start
 for i in md.disasm(pe.get_data(start,end-start),base+start):
  assert i.address-base==cursor;cursor+=i.size
  refs=[]
  for op in i.operands:
   if op.type==capstone.CS_OP_MEM and op.mem.base==capstone.x86_const.X86_REG_RIP:refs.append(hex(i.address-base+i.size+op.mem.disp))
  instructions.append({'rva':hex(i.address-base),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'rip_relative_targets':refs})
 assert cursor==end
 contexts.append({'begin_rva':hex(start),'end_rva':hex(end),'extent_source':'PE unwind','linear_disassembly_complete':True,'runtime_reachability_proven':False,'instructions':instructions})
result={'source_sha256':sha,'contexts':contexts,'observed_status_literals':['0xc0000409','0xc0000417'],'hypotheses':[{'slot_rva':'0x20a0400','candidate_API':'GetCurrentProcess','basis':'Used before the other slot in three small unwind-bounded error/termination-like contexts; RAX moved to RCX. This pattern fits but does not uniquely prove this API.'},{'slot_rva':'0x20a0798','candidate_API':'TerminateProcess','basis':'Receives result of first slot in RCX and a 32-bit status in EDX. Tailcalled in contexts with 0xc0000409 and 0xc0000417. Public CRT docs describe the analogous termination sequence.'}],'runtime_import_target_confirmation':False,'hypothesis_not_promoted_to_Ghidra_function_name':True,'source_reference':'https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/invalid-parameter-functions?view=msvc-170','not_proven':'Actual pointer targets, execution in the user crash, telemetry or network identity.'}
(a.out/'crt-contexts.json').write_text(json.dumps(result,indent=2)+'\n')
(a.out/'crt-contexts.txt').write_text('\n\n'.join(c['begin_rva']+'..'+c['end_rva']+'\n'+'\n'.join(i['rva']+' '+i['bytes']+' '+i['mnemonic']+' '+i['operands'] for i in c['instructions']) for c in contexts)+'\n')
print('Three small contexts extracted, bytes unchanged; API identities are hypotheses.')
