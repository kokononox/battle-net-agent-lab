from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import json,struct,hashlib
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True
r=json.load(open('/data/wlab-handler-triage/scope-tables.json'));out=[]
s,z=p.dirs[3];ranges=[struct.unpack('<III',p.read(a,12)) for a in range(s,s+z,12)]
for k in r['callback_counts']:
 a=int(k,16);ins=[]
 for i in m.disasm(p.read(a,192),a):
  ins.append({'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
  if i.mnemonic in ['jmp','ret','call'] or len(ins)>=26:break
 row={'rva':a,'prefix_only':True,'instructions':ins,'scope_links':[{'function_begin':t['function_begin'],'handler_data_rva':t['handler_data_rva'],'scope':x} for t in r['tables'] for x in t['scopes'] if x['filter_or_finally']==a]}
 if a==0x1f4dc80:
  i=next(m.disasm(p.read(a,15),a,count=1));assert i.mnemonic=='jmp' and i.operands[0].mem.base==X86_REG_RIP;slot=a+i.size+i.operands[0].mem.disp
  loc=p.loc(slot,8)
  row['disk_indirect_slot']={'rva':slot,**loc,'qword':p.u(slot,'<Q') if loc['file_backed'] else None,'raw_bytes':p.read(slot,8).hex() if loc['file_backed'] else None,'runtime_value_known':False}
 if a==0x17dcd50:row['constant_return_stub']={'bytes':p.read(a,6).hex(),'u32_return':0xffffffff,'signed_return':-1}
 row['containing_runtime_functions']=[list(t) for t in ranges if t[0]<=a<t[1]]
 out.append(row)
Path('/data/wlab-handler-triage/callback-prefixes.json').write_text(json.dumps({'sha256':hashlib.sha256(p.b).hexdigest(),'callbacks':out,'scope':'Only prefixes and metadata links, not complete callback semantics.'},indent=2))
for row in out[:3]:print(hex(row['rva']),'range',row['containing_runtime_functions'],'extra',row.get('disk_indirect_slot',row.get('constant_return_stub',{})))
