"""Entry-connected initializer tables. On-disk pointers are not runtime targets."""
from pathlib import Path
import struct,json,hashlib,bisect
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_AC_WRITE
from capstone.x86 import *
from pe_manual import PE
from reachability import walk
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';assert hashlib.sha256(p.b).hexdigest()==PIN
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
ranges=[('process_first',0x209f350,0x209f388,0x200638e,0x2006387,0x2006395,0x2013d04),('process_second',0x209f1f8,0x209f330,0x20063ae,0x20063a7,0x20063b5,0x2013cc0),('thread_initializers',0x209f340,0x209f348,0x20031d0,0x20031d7,None,None)]
pr,ps=p.dirs[3];bounds=[struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12)];bybegin=dict(bounds)
def ins(a):
 i=next(md.disasm(p.read(a,15),a,count=1));return {'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
tables=[];functions=[]
for role,lo,hi,loadlo,loadhi,call,callee in ranges:
 entries=[]
 for a in range(lo,hi,8):
  v=p.u(a,'<Q');entries.append({'slot_rva':a,'disk_qword':v,'target_rva':v-p.base if v else None})
 tables.append({'role':role,'begin':lo,'end_exclusive':hi,'bound_loads':[ins(loadlo),ins(loadhi)],'call_site':ins(call) if call else None,'callee':callee,'entries':entries})
 for e in entries:
  a=e['target_rva']
  if a is None:continue
  if a not in bybegin:
   functions.append({'begin':a,'table_role':role,'table_slot':e['slot_rva'],'status':'not_exact_pdata_entry_unresolved','closed_under_stated_model':False,'instructions':[],'call_or_external_jmp_sites':[],'nonstack_explicit_writes':[],'rip_operands':[],'computed_memory_operands':[],'pe_hints':[]});continue
  row,nodes=walk(p.read,a,bybegin[a],cap=10000);row.update({'table_role':role,'table_slot':e['slot_rva']});instructions=[];calls=[];writes=[];rip=[];hints=[];computed=[]
  for addr,i in sorted(nodes.items()):
   rec={'rva':addr,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str};instructions.append(rec)
   if i.mnemonic in ['call','jmp'] and (i.mnemonic=='call' or i.operands[0].type!=X86_OP_IMM or not a<=i.operands[0].imm<bybegin[a]):calls.append(rec)
   for op in i.operands:
    if op.type==X86_OP_MEM and i.mnemonic not in ['lea','nop']:
     if op.access&CS_AC_WRITE and op.mem.base not in [X86_REG_RSP,X86_REG_RBP]:writes.append({**rec,'disp':op.mem.disp,'base':i.reg_name(op.mem.base),'index':i.reg_name(op.mem.index)})
     if op.mem.base==X86_REG_RIP:
      t=addr+i.size+op.mem.disp;rip.append({**rec,'target_rva':t,'access':op.access})
     elif op.mem.base not in [X86_REG_RSP,X86_REG_RBP]:computed.append(rec)
     if op.mem.disp==0x3c:hints.append({**rec,'reason':'PE_offset_heuristic_only'})
    if op.type==X86_OP_IMM and (op.imm&0xffffffff) in [0x5a4d,0x4550,0x2210000,0x2270000,0x5d0000]:hints.append({**rec,'reason':'PE_or_section_constant_heuristic_only'})
  row.update({'instructions':instructions,'call_or_external_jmp_sites':calls,'nonstack_explicit_writes':writes,'rip_operands':rip,'computed_memory_operands':computed,'pe_hints':hints});functions.append(row)
# Record loop bodies and PE predicate for independent boundary/branch checks.
loops=[]
for a in [0x2013d04,0x2013cc0,0x2003274]:
 row,nodes=walk(p.read,a,bybegin[a]);row['instructions']=[ins(x) for x in sorted(nodes)];loops.append(row)
out={'sha256':PIN,'tables':tables,'functions':functions,'support_bodies':loops,'claims':{'consumer_identified':False,'runtime_execution_observed':False,'decryptor_identified':False},'limitations':['All targets are on-disk pointer values, not runtime bindings.','Process array loops execute only after preceding checks succeed; first loop can stop on nonzero return.','No exceptions, self-modification or external midfunction entries modeled.','Computed addresses, call side effects and complete value flows not resolved.','Closed means closed only under the restricted reused flag/CFG model.']}
(D/'reports/arrays.json').write_text(json.dumps(out,indent=2)+'\n')
print('TABLES',[(x['role'],len(x['entries']),sum(e['target_rva'] is not None for e in x['entries'])) for x in tables]);print('FUNCTIONS',len(functions),'CLOSED',sum(f['closed_under_stated_model'] for f in functions))
for f in functions:print(hex(f['begin']),'nodes',len(f['instructions']),'closed',f['closed_under_stated_model'],'calls',len(f['call_or_external_jmp_sites']),'writes',len(f['nonstack_explicit_writes']),'PEhints',len(f['pe_hints']))
