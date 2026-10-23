"""Read-only, build-pinned guard dispatch metadata and bounded shared-helper review."""
from pathlib import Path
import hashlib,json,struct,pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_AC_WRITE,CS_AC_READ
from capstone.x86 import *
from pe_manual import PE
from reachability import walk
D=Path(__file__).resolve().parents[1];path=Path('/data/wlab-inputs/wow_loader.dll');p=PE(path);PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';assert hashlib.sha256(p.b).hexdigest()==PIN
pp=pefile.PE(data=p.b);cfg=pp.DIRECTORY_ENTRY_LOAD_CONFIG.struct;md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True

def record(a):
 i=next(md.disasm(p.read(a,15),a,count=1));return {'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
fields=[]
for name in ['GuardCFDispatchFunctionPointer','GuardXFGDispatchFunctionPointer']:
 val=getattr(cfg,name);slot=val-p.base;target=p.u(slot,'<Q')-p.base
 fields.append({'field':name,'relative_offset':cfg.get_field_relative_offset(name),'value_va':val,'slot_rva':slot,'slot_disk_qword':p.u(slot,'<Q'),'target_rva':target,'target_instruction':record(target)})
# On-disk thunk chains only. Deliberately NOT a runtime resolver.
def chain(slot):
 out=[]
 for _ in range(4):
  target=p.u(slot,'<Q')-p.base;i=next(md.disasm(p.read(target,15),target,count=1));row={'slot_rva':slot,'disk_target_rva':target,'instruction':record(target)};out.append(row)
  if i.mnemonic=='jmp' and i.operands[0].type==X86_OP_REG and i.operands[0].reg==X86_REG_RAX:return {'steps':out,'terminal':'jmp_rax_on_disk','runtime_binding_confirmed':False}
  assert i.mnemonic=='jmp' and i.operands[0].type==X86_OP_MEM and i.operands[0].mem.base==X86_REG_RIP
  slot=target+i.size+i.operands[0].mem.disp;row['next_slot_rva']=slot
 raise AssertionError('chain bound')
chains=[chain(x['slot_rva']) for x in fields]
call_sites=[]
for a,role in [(0x2013d2b,'process_first_xfg'),(0x2013ce7,'process_second_xfg'),(0x20031e8,'thread_cf')]:
 i=next(md.disasm(p.read(a,15),a,count=1));assert i.mnemonic=='call' and i.operands[0].type==X86_OP_MEM and i.operands[0].mem.base==X86_REG_RIP
 slot=a+i.size+i.operands[0].mem.disp;call_sites.append({**record(a),'role':role,'slot_rva':slot,'load_config_field':next(x['field'] for x in fields if x['slot_rva']==slot)})
pr,ps=p.dirs[3];bounds=dict(struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12))
helper,nodes=walk(p.read,0x957f00,bounds[0x957f00]);helper['instructions']=[record(a) for a in sorted(nodes)];helper['nonstack_memory']=[];helper['calls']=[]
for a,i in sorted(nodes.items()):
 if i.mnemonic=='call':helper['calls'].append(record(a))
 for op in i.operands:
  if op.type==X86_OP_MEM and i.mnemonic not in ['lea','nop'] and op.mem.base not in [X86_REG_RSP,X86_REG_RBP]:
   helper['nonstack_memory'].append({**record(a),'base':i.reg_name(op.mem.base),'index':i.reg_name(op.mem.index),'disp':op.mem.disp,'read':bool(op.access&CS_AC_READ),'write':bool(op.access&CS_AC_WRITE),'rip_target_rva':a+i.size+op.mem.disp if op.mem.base==X86_REG_RIP else None})
caller_evidence=[]
for start in [0x1ef7640,0xa86990]:
 row,ns=walk(p.read,start,bounds[start]);caller_evidence.append({'begin':start,'end':bounds[start],'closed_under_model':row['closed_under_stated_model'],'instructions':[record(a) for a in sorted(ns)]})
result={'input_sha256':PIN,'image_base':p.base,'load_config_rva':p.dirs[10][0],'load_config_directory_size':p.dirs[10][1],'load_config_struct_size':cfg.Size,'guard_flags':cfg.GuardFlags,'fields':fields,'disk_chains':chains,'call_sites':call_sites,'helper':helper,'caller_evidence':caller_evidence,'claims':{'disk_guard_dispatch_chain_identified':True,'runtime_guard_binding_verified':False,'all_initializer_targets_execute':False,'eid_consumer_identified':False,'decryptor_identified':False,'cpu_bios_send_chain_identified':False},'reference':'https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64'}
(D/'reports/evidence.json').write_text(json.dumps(result,indent=2)+'\n');print('fields',[(x['field'],hex(x['slot_rva'])) for x in fields]);print('chains',[(len(x['steps']),x['terminal']) for x in chains]);print('helper',len(nodes),'closed',helper['closed_under_stated_model'],'calls',len(helper['calls']));print('nonstack writes',[(hex(x['rva']),x['asm']) for x in helper['nonstack_memory'] if x['write']])
