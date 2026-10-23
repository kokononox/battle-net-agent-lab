from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import json,hashlib,struct,subprocess,tempfile
root=Path('/data/wlab-api-identity-gate');p=PE(Path('/data/wlab-inputs/wow_loader.dll'));digest=hashlib.sha256(p.b).hexdigest();assert digest=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
a,end=0x20062ec,0x2006320;raw=p.read(a,end-a);m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;nodes=[];slots=[]
for i in m.disasm(raw,a):
 nodes.append({'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
 if i.mnemonic in ['call','jmp']:
  op=i.operands[0];assert op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP
  slots.append({'site':i.address,'kind':i.mnemonic,'slot_rva':i.address+i.size+op.mem.disp})
assert slots[0]['slot_rva']==0x20a0750
assert any(n['asm']=='mov edx, 0xc0000409' for n in nodes)
# Independently check entire block boundaries with GNU objdump, no runtime execution.
with tempfile.TemporaryDirectory() as td:
 f=Path(td)/'wrapper.bin';f.write_bytes(raw)
 text=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+hex(a),str(f)],text=True,capture_output=True,check=True).stdout
 decoded=[]
 for line in text.splitlines():
  q=line.split('\t')
  if len(q)<3:continue
  try:addr=int(q[0].strip().rstrip(':'),16)
  except ValueError:continue
  decoded.append((addr,bytes.fromhex(q[1].strip())))
 assert decoded==[(n['rva'],bytes.fromhex(n['bytes'])) for n in nodes]
# Rel32 targets independently reconstructed from instruction bytes.
for n,s in zip([n for n in nodes if n['asm'].startswith(('call','jmp'))],slots):
 b=bytes.fromhex(n['bytes']);assert n['rva']+len(b)+struct.unpack('<i',b[-4:])[0]==s['slot_rva']
r={'sha256':digest,'range':[a,end],'raw_bytes':raw.hex(),'instructions':nodes,'indirect_slots':slots,'static_pattern':'RCX saved; RCX set to zero before same unresolved slot; original RCX passed to a second slot; result from third slot passed to tail slot with EDX=0xC0000409. Consistent with error-handling/termination plumbing, but API names are not proven.','hypothesis':{'slot_rva':0x20a0750,'candidate_api':'SetUnhandledExceptionFilter','status':'unconfirmed; consistency hypothesis only','support':['zero first argument at several call sites','return saved as candidate callback elsewhere','shared short wrapper has error-handling-shaped call sequence'],'not_evidence':['runtime pointer','named import binding','matched export address']},'official_contracts':[{'url':'https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter','contract':'NULL selects default handling; return is previous filter address.'},{'url':'https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter','contract':'Takes EXCEPTION_POINTERS pointer; returns LONG disposition.'}],'verification':{'independent_objdump_boundaries':len(nodes),'indirect_slot_displacements_verified':len(slots),'runtime_probe_performed':False},'next_gate':{'requested_live_memory_bytes':8,'location':'loaded wow_loader.dll base + 0x20A0750','required_identity':'same process creation identity, module path/base/size, exact pinned file SHA and stable mapping','read_policy':'one bounded read only if committed/readable and mapping matches module; stop on guard/noaccess/identity change; do not change protection or attach debugger','resolution_policy':'compare captured pointer with exact export addresses of matching loaded Windows modules; retain all aliases; unresolved/hooked/non-export addresses stay unresolved; do not chase trampolines','success_criterion':'Unique supported export match confirms current binding, not page-preparation semantics. Standard API binding would deprioritize this branch as a direct decryptor search.'}}
(root/'review.json').write_text(json.dumps(r,indent=2));print('instructions',len(nodes),'slots',[(hex(s['site']),hex(s['slot_rva'])) for s in slots]);print('API identity remains unconfirmed; live probe not built or run')
