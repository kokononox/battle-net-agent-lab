"""Validate instruction alignment and bounded intrafunction reachability of prior xrefs.
Does NOT execute target code or prove an application call/dataflow.
"""
import sys,json,struct,collections
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
R=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/data/wow-static');d=json.load(open(R/'trace/target-references.json'));md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
out=[]
for file in d['files']:
 pe=pefile.PE(str(R/'raw'/file['file']),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
 for x in file['rip_candidates']:
  fr=x['unwind_function'];a=int(fr['begin_rva'],16);z=int(fr['end_rva'],16);target=int(x['instruction_rva'],16)
  code=pe.get_data(a,z-a);linear=list(md.disasm(code,base+a));ids={i.address-base:n for n,i in enumerate(linear)};pos=ids.get(target)
  evidence={'file':file['file'],'target_rva':hex(target),'reference_target':x['target'],'unwind_range':fr,'linear_decoded_bytes':sum(i.size for i in linear),'unwind_range_bytes':z-a,'target_on_linear_instruction_boundary':pos is not None,'neighborhood':[]}
  if pos is not None:
   evidence['neighborhood']=[{'rva':hex(i.address-base),'instruction':i.mnemonic+' '+i.op_str} for i in linear[max(0,pos-7):pos+9]]
  todo=collections.deque([a]);seen=set();branches=0;indirect=0;reached=False;limit=12000
  while todo and len(seen)<limit:
   pc=todo.popleft()
   if pc in seen or not a<=pc<z:continue
   seen.add(pc)
   if pc==target:reached=True
   ins=next(md.disasm(code[pc-a:pc-a+15],base+pc,count=1),None)
   if not ins:continue
   if ins.group(CS_GRP_RET) or ins.mnemonic in ('int3','ud2','hlt'):continue
   nxt=pc+ins.size
   if ins.group(CS_GRP_JUMP):
    if ins.operands and ins.operands[0].type==X86_OP_IMM:
     dst=ins.operands[0].imm-base;branches+=1
     if a<=dst<z:todo.append(dst)
    else:indirect+=1
    if ins.mnemonic not in ('jmp','ljmp'):todo.append(nxt)
   else:todo.append(nxt)
  evidence.update({'bounded_cfg_instruction_starts':len(seen),'direct_branches':branches,'indirect_jump_sites_unresolved':indirect,'target_reachable_from_unwind_begin_in_overapproximation':reached,'cfg_limit_hit':bool(todo),'calls_assumed_returning':True,'conditional_branch_conditions_not_evaluated':True,'runtime_reachability_proven':False,'dataflow_to_send_proven':False})
  out.append(evidence)
  print(file['file'],hex(target),'boundary',pos is not None,'cfg',reached,'nodes',len(seen),'indirect',indirect,flush=True)
(R/'trace/code-candidate-validation.json').write_text(json.dumps(out,indent=2)+'\n')
