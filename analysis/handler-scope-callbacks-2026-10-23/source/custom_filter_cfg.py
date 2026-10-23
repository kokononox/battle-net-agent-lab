from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import json,hashlib,struct
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));assert hashlib.sha256(p.b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
rva,size=p.dirs[3];ranges=[struct.unpack('<III',p.read(a,12)) for a in range(rva,rva+size,12)];start,end,unwind=next(t for t in ranges if t[0]==0xc59140)
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True
inv={'je':'jne','jne':'je','jg':'jle','jle':'jg','jge':'jl','jl':'jge','ja':'jbe','jbe':'ja','jae':'jb','jb':'jae','js':'jns','jns':'js','jo':'jno','jno':'jo','jp':'jnp','jnp':'jp'}
def dec(a):
 assert start<=a<end,hex(a)
 i=next(m.disasm(p.read(a,min(15,end-a)),a,count=1),None);assert i is not None,hex(a);return i
nodes={};todo=[start];pairs=[];effects=[];escapes=[]
while todo:
 a=todo.pop()
 if a in nodes:continue
 if not start<=a<end:escapes.append(hex(a));continue
 i=dec(a);n=a+i.size;succ=[];rule=None
 if i.mnemonic in inv:
  assert i.operands[0].type==X86_OP_IMM
  target=i.operands[0].imm
  j=dec(n);bridge=None
  if j.mnemonic in ['sal','shl','shr','sar','rol','ror'] and j.operands[-1].type==X86_OP_IMM and j.operands[-1].imm==0 and j.operands[0].type==X86_OP_REG:
   bridge=j;j=dec(j.address+j.size)
  if j.mnemonic==inv[i.mnemonic] and j.operands[0].type==X86_OP_IMM and j.operands[0].imm==target:
   rule='complementary branches with unchanged flags and identical target';succ=[target]
   pairs.append({'first':a,'second':j.address,'bridge_rva':bridge.address if bridge else None,'bridge_semantics':'register shift by zero preserves value and flags' if bridge else None,'target':target,'bytes':(i.bytes+(bridge.bytes if bridge else b'')+j.bytes).hex(),'mnemonics':[i.mnemonic,j.mnemonic]})
  else:succ=[target,n]
 elif i.mnemonic=='jmp':
  if i.operands[0].type==X86_OP_IMM:succ=[i.operands[0].imm]
  else:effects.append({'rva':a,'kind':'indirect_jump'} )
 elif i.mnemonic in ['ret','retf']:pass
 elif i.mnemonic=='call':effects.append({'rva':a,'kind':'call','asm':i.op_str});succ=[n]
 else:succ=[n]
 for op in i.operands:
  if op.type==X86_OP_MEM:
   mem=op.mem;kind='rip_relative' if mem.base==X86_REG_RIP else 'stack_rsp' if mem.base==X86_REG_RSP and not mem.index else 'other'
   if i.mnemonic=='lea':access='address_only'
   elif i.mnemonic=='nop':access='none_nop'
   else:access=('read' if op.access&CS_AC_READ else '')+('write' if op.access&CS_AC_WRITE else '') or 'unknown'
   effects.append({'rva':a,'kind':kind,'access':access,'address':hex(n+mem.disp) if kind=='rip_relative' else None,'asm':i.mnemonic+' '+i.op_str})
 nodes[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'successors':succ,'rule':rule};todo.extend(succ)
occ=set();overlaps=[]
for a,v in nodes.items():
 span=set(range(a,a+len(bytes.fromhex(v['bytes']))));
 if occ&span:overlaps.append(hex(a))
 occ|=span
report={'sha256':hashlib.sha256(p.b).hexdigest(),'range':[start,end],'unwind_rva':unwind,'nodes':[nodes[a] for a in sorted(nodes)],'complementary_pairs':pairs,'memory_and_transfer_effects':effects,'escapes':escapes,'overlaps':overlaps,'scope':'Static reachable instruction overapproximation; complementary branch pairs normalized. No runtime execution. Implicit push/pop/ret stack effects not included in explicit memory inventory.','claims':{'decryption_identified':False,'page_writer_identified':False,'send_proven':False}}
Path('/data/wlab-handler-triage/custom-filter-cfg.json').write_text(json.dumps(report,indent=2));print('range',hex(start),hex(end),'nodes',len(nodes),'pairs',len(pairs),'escapes',escapes,'overlaps',overlaps)
from collections import Counter
print('effects',dict(Counter((e['kind'],e.get('access')) for e in effects)))
print('nonlocal effect count',sum(e['kind'] in ['call','indirect_jump'] or (e['kind']=='other' and e.get('access') not in ['address_only','none_nop']) for e in effects))
