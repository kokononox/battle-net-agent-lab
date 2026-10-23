from pathlib import Path
from pe_manual import PE
from capstone import *
from capstone.x86 import *
import struct,json,hashlib
root=Path('/data/wlab-slot-provenance');p=PE(Path('/data/wlab-inputs/wow_loader.dll'));digest=hashlib.sha256(p.b).hexdigest();assert digest=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True
start,end=0x902a40,0x905aa6;raw=p.read(start,end-start);candidates={}
for off in range(len(raw)-3):
 if raw[off:off+4]!=struct.pack('<I',0x338):continue
 for back in range(1,12):
  a=start+off-back
  if a<start:continue
  i=next(m.disasm(p.read(a,15),a,count=1),None)
  if not i or i.disp_offset!=back:continue
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RSP and op.mem.disp==0x338 and not op.mem.index:
    candidates[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'access':('read' if op.access&CS_AC_READ else '')+('write' if op.access&CS_AC_WRITE else '')}
# Decode the linked block from a first-dispatch frontier, not an arbitrary byte offset.
path=[0x902b54,0x902b58,0x902b5d,0x902b5f,0x902b64,0x902d90,0x902d95,0x902d9b,0x902da0,0x902da6,0x902dab,0x902db1,0x902db6,0x902dbc]
pathnodes=[]
for idx,a in enumerate(path):
 i=next(m.disasm(p.read(a,15),a,count=1));pathnodes.append({'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
 if idx+1<len(path):assert path[idx+1] in [a+i.size]+([i.operands[0].imm] if i.mnemonic.startswith('j') else [])
block=[]
for i in m.disasm(p.read(0x902dbc,0x902e1c-0x902dbc),0x902dbc):block.append({'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
assert block[-1]['rva']==0x902e14 and block[-1]['asm']=='mov qword ptr [rsp + 0x338], rax'
assert block[-2]['rva']==0x902e0e and block[-2]['asm'].startswith('call qword ptr [rip')
assert block[-3]['asm']=='xor ecx, ecx'
slot=0x902e14+p.u(0x902e10,'<i');assert slot==0x20a0750
value=p.u(slot,'<Q');assert value==0x20a1a98;record=p.read(value,30)
refs=[]
name,vs,va,rs,ro=p.sections[0];b=p.b[ro:ro+rs]
for op in [b'\xff\x15',b'\xff\x25']:
 pos=0
 while True:
  pos=b.find(op,pos)
  if pos<0:break
  if pos+6<=len(b) and va+pos+6+struct.unpack_from('<i',b,pos+2)[0]==slot:refs.append(va+pos)
  pos+=1
r={'sha256':digest,'function_range':[start,end],'stack_slot_candidates':[candidates[a] for a in sorted(candidates)],'scan_scope':'Exact RSP+0x338 displacements in this function only. Overlapping prefix decodes retained. Not complete alias/interprocedural analysis.','dispatch_path_to_frontier':pathnodes,'path_scope':'Syntactic dispatcher path only; feasible runtime state, stack initialization and execution sequence are not proved.','initialization_block':block,'local_predicate':{'site':0x902ddc,'asm':'jae 0x905776','fallthrough_required_for_calls_and_store':True,'predicate_values':'stack-derived and unresolved'},'return_origin':{'call_site':0x902e0e,'call_slot_rva':slot,'known_argument':'ECX=0, hence RCX=0, immediately before call','store_site':0x902e14,'stack_offset':0x338,'relation':'On normal return, RAX is stored immediately; no intervening instruction. Other argument registers are not resolved.'},'disk_call_slot':{'rva':slot,**p.loc(slot,8),'qword':value,'possible_name_record_rva':value,'candidate_name_record_first_30_bytes':record.hex(),'api_name_identified':False,'runtime_target_known':False,'interpretation':'Disk qword is not treated as the runtime target. Possible import-name interpretation is unconfirmed; candidate record bytes are zero.'},'raw_ff15_ff25_reference_sites':sorted(refs),'downstream_store':{'load_rva':0x90593b,'store_rva':0x905943,'destination_slot_rva':0x219bdc8,'bytes':p.read(0x90593b,15).hex(),'relation':'If no intervening writes/aliases change the local slot, loaded value is the earlier saved call return. Execution order and whole-function aliases are unresolved.'},'claims':{'local_return_store_relation_verified':True,'api_identity_proven':False,'runtime_pointer_recovered':False,'target_page_writer_proven':False,'cpu_bios_send_proven':False}}
(root/'provenance.json').write_text(json.dumps(r,indent=2));print('return saved at',hex(r['return_origin']['store_site']),'call slot',hex(slot),'raw reference sites',[hex(x) for x in sorted(refs)])
