from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import json,hashlib,struct,collections
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));digest=hashlib.sha256(p.b).hexdigest();assert digest=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
s,z=p.dirs[3];ranges=[struct.unpack('<III',p.read(a,12)) for a in range(s,s+z,12)];m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True
old=json.load(open('/data/wlab-export-effects/unwind-inventory.json'))[1];roots=[int(x,16) for x in old['handler_counts']];roots += [0x2005e5c,0x201ff34,0x20201b4];out=[]
for root in roots:
 found=[x for x in ranges if x[0]<=root<x[1]]
 if len(found)!=1:out.append({'root':root,'range_matches':found});continue
 begin,end,u=found[0];todo=[root];nodes={};calls=[];tails=[];constants=[];other=[]
 while todo:
  a=todo.pop()
  if a in nodes:continue
  if not begin<=a<end:tails.append(a);continue
  i=next(m.disasm(p.read(a,min(15,end-a)),a,count=1),None)
  if i is None:raise RuntimeError(('decode',hex(a)))
  n=a+i.size;succ=[]
  if i.mnemonic.startswith('ret'):pass
  elif i.mnemonic=='jmp':
   if i.operands[0].type==X86_OP_IMM:succ=[i.operands[0].imm]
   else:other.append({'rva':a,'asm':i.mnemonic+' '+i.op_str})
  elif i.mnemonic.startswith('j'):
   assert i.operands[0].type==X86_OP_IMM;succ=[i.operands[0].imm,n]
  else:
   succ=[n]
   if i.mnemonic=='call':calls.append({'site':a,'target':i.operands[0].imm if i.operands[0].type==X86_OP_IMM else None,'asm':i.op_str})
  for op in i.operands:
   if op.type==X86_OP_IMM and (op.imm&0xffffffff)>0xffff:constants.append({'site':a,'u32':hex(op.imm&0xffffffff),'asm':i.mnemonic+' '+i.op_str})
  nodes[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'successors':succ};todo.extend(succ)
 occ=set();overlap=[]
 for a,n in nodes.items():
  b=set(range(a,a+len(bytes.fromhex(n['bytes']))))
  if occ&b:overlap.append(a)
  occ|=b
 row={'root':root,'unwind_range':[begin,end],'unwind_rva':u,'nodes':[nodes[a] for a in sorted(nodes)],'calls':calls,'tail_destinations':sorted(set(tails)),'indirect_transfers':other,'constants':constants,'overlaps':overlap};out.append(row)
 print(hex(root),'range',hex(begin),hex(end),'instructions',len(nodes),'calls',[(hex(c['site']),hex(c['target']) if c['target'] else c['asm']) for c in calls],'tails',[hex(t) for t in set(tails)],'overlaps',len(overlap))
 print('constants',constants[:12])
report={'sha256':digest,'roots_from_unwind_inventory':roots[:8],'additional_roots':'first direct callee of handler families, addresses verified at call sites','functions':out,'scope':'Per-function CFG from on-disk bytes, follows direct local branches only. Does not execute inputs, resolve indirect calls, follow callees, or model exceptions. Not a decryption claim.'}
Path('/data/wlab-handler-triage/triage.json').write_text(json.dumps(report,indent=2))
