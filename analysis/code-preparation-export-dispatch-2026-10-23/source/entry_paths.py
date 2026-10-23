from pathlib import Path
from pe_manual import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
import json,struct
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
out=[]
for name in ['Wow.exe','wow_loader.dll']:
 p=PE(Path('/data/wlab-inputs')/name)
 roots=[('entry',p.ep)]+[('tls',x['callback_rva']) for x in p.tls()]
 if name=='wow_loader.dll': roots += [('export_'+str(x['ordinal']),x['rva']) for x in p.exports()]
 seen=set()
 for role,r in roots:
  if r in seen:continue
  seen.add(r)
  ins=[]
  for i in md.disasm(p.read(r,192),p.base+r):
   ins.append({'rva':hex(i.address-p.base),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
   if len(ins)>=35 or i.mnemonic in ['ret','jmp']:break
  out.append({'file':name,'role':role,'rva':hex(r),'instructions':ins})
Path('/data/wlab-code-preparation-review/entry-paths.json').write_text(json.dumps(out,indent=2))
for row in out:
 print(row['file'],row['role'],row['rva'])
 for i in row['instructions']:print(i['rva'],i['asm'])
