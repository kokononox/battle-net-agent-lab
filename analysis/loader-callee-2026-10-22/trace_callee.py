"""Bounded static normal-flow CFG, no execution or byte modification."""
from pathlib import Path
import argparse,sys,os,json,hashlib,struct,collections
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile,capstone
from capstone.x86_const import X86_REG_RIP
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/wow_loader.dll'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
b=a.input.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
pe=pefile.PE(data=b);base=pe.OPTIONAL_HEADER.ImageBase;begin=0x17df7f0;end=0x17e06c9
assert any(e.struct.BeginAddress==begin and e.struct.EndAddress==end for e in pe.DIRECTORY_ENTRY_EXCEPTION)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
pairs={'je':'jne','jne':'je','jle':'jg','jg':'jle','jl':'jge','jge':'jl','ja':'jbe','jbe':'ja','jae':'jb','jb':'jae','jo':'jno','jno':'jo','js':'jns','jns':'js','jp':'jnp','jnp':'jp'}
def one(r):
 if not begin<=r<end:return None
 return next(md.disasm(pe.get_data(r,min(15,end-r)),base+r,count=1),None)
def target(i):return i.operands[0].imm-base if i.operands and i.operands[0].type==capstone.CS_OP_IMM else None
def walk(normalize):
 todo=[begin];nodes={};proofs=[];outside=set();unresolved=[]
 while todo:
  r=todo.pop()
  if r in nodes:continue
  if not begin<=r<end:outside.add(r);continue
  i=one(r)
  if i is None:unresolved.append({'rva':hex(r),'reason':'decode_failure'});continue
  n=r+i.size;t=target(i);m=i.mnemonic;edges=[]
  # Collapse only adjacent complementary Jcc, or TEST/logical-op followed by OF/CF-based Jcc.
  j=one(n)
  if normalize and r in globals().get('constant_branches',{}):
   proof=constant_branches[r];edges=[int(proof['chosen_rva'],16)];proofs.append(proof)
  elif normalize and m in pairs and j and j.mnemonic==pairs[m] and target(j)==t and t is not None:
   edges=[t];proofs.append({'kind':'adjacent_complementary_Jcc','first_rva':hex(r),'first_bytes':i.bytes.hex(),'second_rva':hex(n),'second_bytes':j.bytes.hex(),'target_rva':hex(t)})
  elif normalize and m in ('test','and','or','xor') and j and j.mnemonic in ('jno','jo','jae','jb') and target(j) is not None:
   # Keep the Jcc in graph; its constant edge is applied only after predecessor check below.
   edges=[n]
  elif m.startswith('ret') or m in ('ud2','int3','hlt'):edges=[]
  elif m=='jmp':
   if t is None:unresolved.append({'rva':hex(r),'reason':'indirect_jump'})
   else:edges=[t]
  elif m.startswith('j') or m.startswith('loop'):edges=[n]+([t] if t is not None else [])
  else:edges=[n]
  nodes[r]={'rva':hex(r),'bytes':i.bytes.hex(),'mnemonic':m,'operands':i.op_str,'successors':[hex(e) for e in edges]}
  todo.extend(edges)
 # Constant-flag branch pruning uses a unique-predecessor check from the raw CFG.
 return nodes,proofs,outside,unresolved
raw,_,rawout,rawunknown=walk(False)
constant_branches={}
for r,v in raw.items():
 i=one(r);n=r+i.size;j=one(n)
 if i.mnemonic not in ('test','and','or','xor') or not j or j.mnemonic not in ('jno','jo','jae','jb'):continue
 pred=[x for x,z in raw.items() if hex(n) in z['successors']]
 if pred!=[r]:continue
 t=target(j)
 if t is None:continue
 chosen=t if j.mnemonic in ('jno','jae') else n+j.size
 constant_branches[n]={'kind':'logical_op_clears_OF_CF_unique_raw_predecessor','preceding_rva':hex(r),'preceding_bytes':i.bytes.hex(),'branch_rva':hex(n),'branch_bytes':j.bytes.hex(),'chosen_rva':hex(chosen)}
nodes,proofs,outside,unknown=walk(True)
# Distinct instruction-range overlaps are evidence of ambiguous decoding, not two runtime streams.
intervals=sorted((r,r+len(bytes.fromhex(i['bytes']))) for r,i in nodes.items())
overlaps=[{'first':hex(x),'second':hex(y)} for k,(x,e) in enumerate(intervals) for y,z in intervals[k+1:] if y<e]
calls=[nodes[r] for r in sorted(nodes) if nodes[r]['mnemonic']=='call'];refs=[]
for r in sorted(nodes):
 i=one(r)
 for op in i.operands:
  if op.type==capstone.CS_OP_MEM and op.mem.base==X86_REG_RIP:
   t=r+i.size+op.mem.disp;refs.append({'instruction_rva':hex(r),'target_rva':hex(t),'access_size_bytes':op.size,'access_flags_capstone':op.access,'mnemonic':i.mnemonic,'file_bytes':pe.get_data(t,op.size).hex(),'runtime_value_known':False})
imports=[{'dll':d.dll.decode(),'original_first_thunk':hex(d.struct.OriginalFirstThunk),'first_thunk':hex(d.struct.FirstThunk),'entries':[{'name':i.name.decode() if i.name else None,'ordinal':i.ordinal,'slot_rva':hex(i.address-base)} for i in d.imports]} for d in pe.DIRECTORY_ENTRY_IMPORT]
slots=[];iat=pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
for r in (0x20a0400,0x20a0798):
 v=struct.unpack('<Q',pe.get_data(r,8))[0];slots.append({'rva':hex(r),'file_bytes':pe.get_data(r,8).hex(),'file_value':hex(v),'within_declared_IAT':iat.VirtualAddress<=r<iat.VirtualAddress+iat.Size,'bytes_at_file_value_RVA_32':pe.get_data(v,32).hex(),'named_imports_mapped_to_slot':[{'dll':d['dll'],'entry':i} for d in imports for i in d['entries'] if i['slot_rva']==hex(r)],'runtime_target_known':False})
result={'source_sha256':sha,'function_rva':[hex(begin),hex(end)],'extent_source':'PE exception/unwind table','raw_recursive_instruction_count':len(raw),'raw_instructions':[raw[r] for r in sorted(raw)],'normalized_instruction_count':len(nodes),'proofs':proofs,'calls':calls,'outside_range_edges':[hex(r) for r in sorted(outside)],'unresolved_control_flow':unknown,'overlapping_instruction_ranges':overlaps,'rip_relative_references':refs,'instructions':[nodes[r] for r in sorted(nodes)],'slots':slots,'declared_IAT_rva':hex(iat.VirtualAddress),'declared_IAT_size':hex(iat.Size),'import_descriptors':imports,'limits':'Syntactic normal-flow overapproximation. Calls not followed and assumed returning. Protected/obfuscated bytes can produce false instruction streams; no runtime reachability, types, API identities or telemetry binding proven.','input_execution_emulation_or_patch':False}
(a.out/'callee-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
(a.out/'callee-disassembly.txt').write_text('\n'.join(f"{i['rva']}  {i['bytes']:30s} {i['mnemonic']} {i['operands']}" for i in result['instructions'])+'\n')
print(json.dumps({k:result[k] for k in ('raw_recursive_instruction_count','normalized_instruction_count','proofs','outside_range_edges','unresolved_control_flow','overlapping_instruction_ranges','calls','slots')},indent=2))
