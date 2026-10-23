"""Independent pefile import validation, FF15/25 scan and bounded resolver triage."""
import json,struct,re,hashlib,bisect
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_RET,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
D=Path(__file__).resolve().parents[1];rows=json.loads((D/'reports/inventory.json').read_text());out=[]
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for row in rows:
 fn=row['binary'];p=pefile.PE('/data/wlab-inputs/'+fn);base=p.OPTIONAL_HEADER.ImageBase;entries=[]
 for kind,attr in [('normal','DIRECTORY_ENTRY_IMPORT'),('delay','DIRECTORY_ENTRY_DELAY_IMPORT')]:
  for d in getattr(p,attr,[]):
   for e in d.imports:entries.append(dict(kind=kind,dll=d.dll.decode(),slot_rva=e.address-base,ordinal=e.ordinal,literal_name=e.name.decode() if e.name and e.ordinal is None else None))
 assert sorted(entries,key=lambda a:a['slot_rva'])==sorted(row['imports'],key=lambda a:a['slot_rva'])
 slots={e['slot_rva']:e for e in entries};direct=[]
 for s in p.sections:
  if not s.Characteristics&0x20000000:continue
  b=s.get_data()
  for m in re.finditer(b'\xff[\x15\x25]',b):
   at=m.start()
   if at+6>len(b):continue
   r=int(s.VirtualAddress)+at;target=r+6+struct.unpack_from('<i',b,at+2)[0]
   if target in slots:direct.append(dict(rva=r,bytes=b[at:at+6].hex(),slot_rva=target,kind='call' if b[at+1]==0x15 else 'jmp'))
 observed={(x['rva'],x['bytes'],x['slot_rva']) for x in row['rip_candidates']}
 assert all((x['rva'],x['bytes'],x['slot_rva']) in observed for x in direct)
 # Relocation-backed VA pointers to actual IAT slots, not API implementations.
 reloc=[]
 for block in getattr(p,'DIRECTORY_ENTRY_BASERELOC',[]):
  for e in block.entries:
   if e.type==10:
    value=struct.unpack('<Q',p.get_data(e.rva,8))[0]-base
    if value in slots:reloc.append(dict(slot_rva=e.rva,target_iat_slot_rva=value))
 exact=[]
 for group in row['api_name_strings']:
  pat=group['name'].encode(group['encoding']);width=1 if group['encoding']=='ascii' else 2
  for hit in group['matches']:
   off=hit['file_offset'];before=p.__data__[max(0,off-width):off]
   if before==b'\0'*width:exact.append(dict(name=group['name'],encoding=group['encoding'],**hit))
 triage=[]
 if fn=='libxell.dll':
  chosen=[]
  for x in row['rip_candidates']:
   if x['import_entry']['literal_name']=='GetProcAddress' and x['pdata_owner'] and x['pdata_owner'] not in chosen:chosen.append(x['pdata_owner'])
   if len(chosen)==3:break
  for lo,hi in chosen:
   todo=[lo];seen=set();decoded=[];stops=[];strings=[]
   while todo and len(seen)<1000:
    pc=todo.pop()
    if pc in seen:continue
    if not lo<=pc<hi:continue
    seen.add(pc);ins=next(md.disasm(p.get_data(pc,min(15,hi-pc)),pc,count=1),None)
    if not ins:stops.append(dict(rva=pc,reason='undecodable'));continue
    decoded.append(dict(rva=pc,bytes=ins.bytes.hex(),asm=ins.mnemonic+' '+ins.op_str))
    for op in ins.operands:
     if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
      target=ins.address+ins.size+op.mem.disp
      if ins.mnemonic=='lea':
       raw=p.get_data(target,200).split(b'\0',1)[0]
       if len(raw)>2 and all(32<=c<127 for c in raw):strings.append(dict(instruction_rva=pc,target_rva=target,text=raw.decode()))
    if ins.group(CS_GRP_RET):continue
    if ins.group(CS_GRP_JUMP):
     if ins.operands[0].type==X86_OP_IMM:todo.append(ins.operands[0].imm)
     else:stops.append(dict(rva=pc,reason='indirect_jump'))
     if ins.mnemonic=='jmp':continue
    todo.append(pc+ins.size)
   calls=[x for x in row['rip_candidates'] if x['rva'] in seen and x['import_entry']['literal_name']=='GetProcAddress']
   triage.append(dict(pdata_begin=lo,pdata_end=hi,reachable_syntactic_instructions=sorted(decoded,key=lambda x:x['rva']),resolver_candidates_on_walk=[x['rva'] for x in calls],rip_lea_printable_strings=strings,stops=stops,limit_reached=bool(todo)))
 out.append(dict(binary=fn,import_agreement=True,independent_ff15_ff25_matches=direct,relocation_backed_pointers_to_iat_slots=reloc,whole_nul_delimited_api_names=exact,resolver_control_triage=triage))
 print(fn,'direct',len(direct),'reloc-to-IAT',len(reloc),'wholeAPI',[(x['name'],hex(x['rva'])) for x in exact],flush=True)
 for t in triage:print('control',hex(t['pdata_begin']),len(t['reachable_syntactic_instructions']),t['rip_lea_printable_strings'],t['stops'])
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n')
