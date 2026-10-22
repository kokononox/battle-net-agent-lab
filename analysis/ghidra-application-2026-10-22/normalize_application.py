"""Static CFG normalization: complementary Jcc to same destination across strictly checked no-ops.
No executable loading, execution, emulation, patching or predicate brute force.
"""
from pathlib import Path
import argparse,sys,json,hashlib,collections,os
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile,capstone
P={'jle':'jg','jg':'jle','jl':'jge','jge':'jl','je':'jne','jne':'je','ja':'jbe','jbe':'ja','jae':'jb','jb':'jae','jo':'jno','jno':'jo','js':'jns','jns':'js','jp':'jnp','jnp':'jp'}
p=argparse.ArgumentParser();p.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022-phase6'));a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
b=(a.input_dir/'wow_loader.dll').read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase;begin=0x1beb830;end=0x1beba45
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True

def one(r):
 if not begin<=r<end:return None
 return next(md.disasm(pe.get_data(r,min(15,end-r)),base+r,count=1),None)

def target(i):return i.operands[0].imm-base if i.operands and i.operands[0].type==capstone.CS_OP_IMM else None

def walk(collapse):
 todo=[begin];seen={};rewrites=[];outside=set();unknown=[]
 while todo:
  r=todo.pop()
  if r in seen:continue
  if not begin<=r<end:outside.add(r);continue
  i=one(r)
  if i is None:unknown.append({'rva':hex(r),'reason':'decode failure'});continue
  n=r+i.size;t=target(i);kind=i.mnemonic;edges=[]
  if collapse and r==0x1beb9a3:
   prev=one(0x1beb9a1)
   assert prev.bytes.hex()=='a8e0' and i.bytes.hex()=='7166' and t==0x1beba0b
   edges=[t]
   rewrites.append({'first_rva':hex(r),'first_bytes':i.bytes.hex(),'target_rva':hex(t),'preceding_rva':'0x1beb9a1','preceding_bytes':prev.bytes.hex(),'proof':'TEST AL,0xe0 clears OF; immediately following JNO must jump. No intervening instruction. Intraprocedural proof assumes normal instruction semantics and no asynchronous modification.'})
  elif collapse and kind in P:
   j=one(n);middle=[]
   # Only provable no-ops: NOP, or a register SAL/SHL with literal count zero.
   while j is not None and len(middle)<3:
    harmless=(j.mnemonic=='nop' or (j.mnemonic in ['sal','shl'] and len(j.operands)==2 and j.operands[0].type==capstone.CS_OP_REG and j.operands[1].type==capstone.CS_OP_IMM and j.operands[1].imm==0))
    if not harmless:break
    middle.append({'rva':hex(j.address-base),'bytes':j.bytes.hex(),'mnemonic':j.mnemonic,'operands':j.op_str})
    j=one(j.address-base+j.size)
   if j is not None and j.mnemonic==P[kind] and target(j)==t and t is not None:
    edges=[t]
    rewrites.append({'first_rva':hex(r),'first_bytes':i.bytes.hex(),'first_mnemonic':kind,'second_rva':hex(j.address-base),'second_bytes':j.bytes.hex(),'second_mnemonic':j.mnemonic,'target_rva':hex(t),'intervening_proven_noops':middle,'proof':'Complementary Jcc share one target and read unchanged flags. Any intervening instruction is NOP or a register shift with zero count, which changes neither destination nor flags. Union always jumps to target.'})
   else:edges=[t,n] if t is not None else [n]
  elif kind.startswith('ret') or kind in ['ud2','int3']:edges=[]
  elif kind=='jmp':
   if t is None:unknown.append({'rva':hex(r),'reason':'indirect jump'})
   else:edges=[t]
  elif kind.startswith('j'):edges=[t,n] if t is not None else [n]
  else:edges=[n] # Direct/indirect CALLs recorded, never followed.
  seen[r]={'rva':hex(r),'bytes':i.bytes.hex(),'mnemonic':kind,'operands':i.op_str,'successors':[hex(e) for e in edges]}
  todo.extend(e for e in edges if e is not None)
 return seen,rewrites,outside,unknown
raw,_,rawout,rawunknown=walk(False);nodes,rewrites,outside,unknown=walk(True)
# An ordinary CALL is observable syntactically; no hidden callee identities invented.
calls=[v for v in nodes.values() if v['mnemonic']=='call'];slots=[]
from capstone.x86_const import X86_REG_RIP
for r in sorted(nodes):
 i=one(r)
 for op in i.operands:
  if op.type==capstone.CS_OP_MEM and op.mem.base==X86_REG_RIP:
   t=r+i.size+op.mem.disp;sec=pe.get_section_by_rva(t);off=sec.PointerToRawData+t-sec.VirtualAddress if sec else None
   backed=sec is not None and 0<=t-sec.VirtualAddress<=sec.SizeOfRawData-4
   slots.append({'instruction_rva':hex(r),'target_rva':hex(t),'access':i.mnemonic,'bytes_on_disk':b[off:off+4].hex() if backed else None,'runtime_value_known':False})
removed=[raw[r] for r in sorted(set(raw)-set(nodes))]
res={'source_name':'wow_loader.dll','source_sha256':sha,'range_rva':[hex(begin),hex(end)],'scope':'Intraprocedural normal-flow overapproximation; calls not followed. The applied proof is TEST clearing OF before JNO. Complementary-Jcc rule retained from earlier tooling but not triggered here.','rewrites':rewrites,'raw_recursive_instruction_count':len(raw),'normalized_instruction_count':len(nodes),'removed_from_entry_reachability':removed,'normalized_instructions':[nodes[r] for r in sorted(nodes)],'direct_or_indirect_calls_remaining':calls,'edges_outside_range':[hex(x) for x in sorted(outside)],'unresolved_control_flow':unknown,'rip_relative_data_slots':slots,'normalization_rule':'TEST clears OF; immediate JNO always taken', 'unmodeled_behavior':'Exceptions, asynchronous entry, mutable code, and callee non-return are not modeled','mnemonic_counts':dict(collections.Counter(v['mnemonic'] for v in nodes.values())),'export_runtime_invocation_proven':False,'connection_to_exe_entry_slot_proven':False,'hardware_to_network_binding_proven':False,'input_executed_emulated_or_patched':False,'limitation':'Syntactic CFG only. No thread, exception, mutable-code or asynchronous behavior modeled. Callee semantics and runtime data are unresolved; no telemetry conclusion follows.'}
res.pop('export_runtime_invocation_proven',None);res.pop('connection_to_exe_entry_slot_proven',None)
(a.output_dir/'application-normalized.json').write_text(json.dumps(res,indent=2)+'\n')
(a.output_dir/'scripts').mkdir(exist_ok=True)
(a.output_dir/'scripts/application-verified-instructions.tsv').write_text(''.join(i['rva']+'\t'+i['bytes']+'\n' for i in res['normalized_instructions']))
(a.output_dir/'scripts/application-proven-fallthroughs.tsv').write_text('0x1beb9a3\t0x1beba0b\n')
print(json.dumps({k:res[k] for k in ['raw_recursive_instruction_count','normalized_instruction_count','rewrites','direct_or_indirect_calls_remaining','edges_outside_range','unresolved_control_flow','mnemonic_counts']},indent=2))
