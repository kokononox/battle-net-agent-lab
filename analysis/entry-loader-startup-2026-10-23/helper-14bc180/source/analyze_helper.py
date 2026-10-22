"""Pinned static helper review. No input PE is loaded or executed."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from z3 import BitVec,Solver,Not,sat,unsat,simplify,substitute,BitVecVal
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
START,END=0x14bc180,0x14c39bd
PRELUDE='4157415641554154565755534881ec080900000f29b424f0080000488b051e40c1004831e048898424e80800008b053d87ca00b9c91cbf6129c131c105a289b68c29c129c181c1a3ccf768894c244c0f57f64c8dbc24e0060000e9d1000000'
def run(inp,out):
 b=inp.read_bytes();assert hashlib.sha256(b).hexdigest()==PIN,'Unsupported binary'
 p=pefile.PE(data=b,fast_load=True);cs=Cs(CS_ARCH_X86,CS_MODE_64)
 def read(r,n):
  matches=[s for s in p.sections if s.VirtualAddress<=r and r+n<=s.VirtualAddress+s.SizeOfRawData];assert len(matches)==1
  s=matches[0];off=s.PointerToRawData+r-s.VirtualAddress;return b[off:off+n]
 def dec(r):
  i=next(cs.disasm(read(r,15),r,count=1),None);assert i is not None;return i
 assert read(START,len(bytes.fromhex(PRELUDE))).hex()==PRELUDE
 d=p.OPTIONAL_HEADER.DATA_DIRECTORY[3];pdata=read(d.VirtualAddress,d.Size)
 assert any(struct.unpack_from('<II',pdata,o)==(START,END) for o in range(0,len(pdata)-11,12))
 x=BitVec('entry_global_u32',32);v=0x61bf1cc9-x;v=v^x;a=x+0x8cb689a2;v=v-a;v=v-a;state=v+0x68f7cca3
 def pred(m,k):return {'jg':lambda:state>k,'jge':lambda:state>=k,'jl':lambda:state<k,'jle':lambda:state<=k,'je':lambda:state==k,'jne':lambda:state!=k}[m]()
 nodes={};leaves=[];checks=[];unknown=[];todo=[(0x14bc2b0,[],None,[],[])]
 while todo:
  addr,pc,last,path,decisions=todo.pop()
  for step in range(100):
   assert START<=addr<END and addr not in path
   i=dec(addr);nodes[addr]={'rva':addr,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};path=path+[addr];n=addr+i.size
   if i.mnemonic=='mov' and i.op_str=='eax, dword ptr [rsp + 0x4c]':addr=n;continue
   if i.mnemonic=='cmp' and i.op_str.startswith('eax, '):last=(addr,int(i.op_str.split(', ')[1],0));addr=n;continue
   if i.mnemonic=='jmp':addr=int(i.op_str,16);continue
   if i.mnemonic in ('jg','jge','jl','jle','je','jne') and last is not None:
    term=pred(i.mnemonic,last[1]);dest=int(i.op_str,16)
    for taken,target in [(True,dest),(False,n)]:
     term2=term if taken else Not(term);s=Solver();s.set(timeout=10000);s.add(*(pc+[term2]));status=s.check()
     decision={'site':addr,'cmp_site':last[0],'mnemonic':i.mnemonic,'constant':last[1],'taken':taken}
     checks.append({'path_decisions':decisions+[decision],'result':str(status)})
     if status==sat:todo.append((target,pc+[term2],last,path,decisions+[decision]))
     elif status!=unsat:unknown.append({'site':addr,'result':str(status)})
    break
   s=Solver();s.set(timeout=10000);s.add(*pc);assert s.check()==sat;w=s.model().eval(x,model_completion=True).as_long();ws=simplify(substitute(state,(x,BitVecVal(w,32)))).as_long()
   leaves.append({'rva':addr,'path':path,'decisions':decisions,'witness_x':w,'witness_state':ws,'first_instruction':i.mnemonic+' '+i.op_str});break
  else:raise ValueError('dispatcher instruction budget')
  if len(leaves)+len(todo)>256:raise ValueError('dispatcher path budget')
 assert not unknown
 parity=Solver();parity.set(timeout=10000);parity.add((state&1)!=0);assert parity.check()==unsat
 global_rva=0x14bc1b3+struct.unpack('<i',read(0x14bc1af,4))[0];disk=struct.unpack('<I',read(global_rva,4))[0]
 disk_state=simplify(substitute(state,(x,BitVecVal(disk,32)))).as_long()
 def matches(leaf,value):
  val=BitVecVal(value,32)
  for q in leaf['decisions']:
   truth=simplify(substitute(pred(q['mnemonic'],q['constant']),(x,val)))
   if str(truth)!=str(q['taken']):return False
  return True
 disk_leaves=[l for l in leaves if matches(l,disk)];assert len(disk_leaves)==1 and disk_leaves[0]['rva']==0x14c2225
 # A separate bounded graph. Rules are annotations, never binary edits.
 def graph(start,end,call,rules,branch_sites):
  ns={};es={};queue=[start]
  while queue:
   a=queue.pop()
   if a in ns:continue
   assert start<=a<end;i=dec(a);n=a+i.size
   ns[a]={'rva':a,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
   if a==call:succ=[]
   elif i.mnemonic.startswith('j'):
    target=int(i.op_str,16)
    if a in rules:succ=[target if rules[a]['decision']=='taken' else n]
    else:assert a in branch_sites;succ=[target,n]
   else:assert i.mnemonic not in ('call','ret');succ=[n]
   es[a]=succ;queue.extend(succ)
  occ=set()
  for a,node in ns.items():
   span=set(range(a,a+len(bytes.fromhex(node['bytes']))));assert not occ&span;occ|=span
  return {'start':start,'stop_call':call,'nodes':[ns[a] for a in sorted(ns)],'edges':[{'from':a,'to':es[a]} for a in sorted(es)],'rules':[{'rva':a,**rule} for a,rule in sorted(rules.items())]}
 # Conditional on disk initial global and the list-like pointer not equaling head.
 # First compare is left unresolved; the equal edge is separately a frontier.
 rules={0x14c2335:{'decision':'taken','reason':'OR AL,0 clears OF; MOV CH,CH preserves flags'},0x14c237c:{'decision':'taken','reason':'fallthrough of adjacent JNP: PF=1; JP is complementary'},0x14c23b2:{'decision':'taken','reason':'arrived through JNP; flags unchanged'},0x14c23bc:{'decision':'taken','reason':'preceding JNP taken; flags unchanged'},0x14c23c8:{'decision':'taken','reason':'arrived through JP; flags unchanged'},0x14c23d9:{'decision':'taken','reason':'TEST clears OF; SAR BH,0 preserves flags'},0x14c2404:{'decision':'taken','reason':'JNO taken; NOP preserves OF'}}
 # Start after the unresolved pointer equality branch to avoid hiding its exit.
 g=graph(0x14c224b,0x14c2455,0x14c2450,rules,{0x14c237a})
 g['condition']='Initial global equals its disk value; pointer comparison at 0x14C2242 is not equal; valid ordinary reads and unchanged code'
 g['unresolved_pointer_branch']={'rva':0x14c2245,'equal_target':0x14c3838,'not_equal_target':0x14c224b}
 wrules={0x15b40b0:{'decision':'taken','reason':'fallthrough of JAE implies CF=1; XCHG BH,BH preserves flags'},0x15b40dd:{'decision':'taken','reason':'JB taken, CF=1 unchanged'},0x15b40e9:{'decision':'taken','reason':'JAE taken, CF=0 unchanged'}}
 wrapper=graph(0x15b40a0,0x15b4119,0x15b410e,wrules,{0x15b40ac})
 wrapper['condition']='Conditional on reaching this wrapper; either CF after stack subtraction is allowed'
 report={'schema':'wlab-helper-review-1','module_sha256':PIN,'function':{'start':START,'end':END,'raw_sha256':hashlib.sha256(read(START,END-START)).hexdigest(),'entry_bytes':PRELUDE},'initial_global':{'rva':global_rva,'disk_u32':disk,'disk_state':disk_state,'disk_only_frontier':0x14c2225,'runtime_invariant':False},'dispatcher':{'start':0x14bc2b0,'nodes':[nodes[a] for a in sorted(nodes)],'leaves':leaves,'branch_checks':checks,'unknown':unknown,'state_always_even':'unsat for counterexample (state & 1) != 0','path_count':len(leaves),'distinct_frontiers':len({l['rva'] for l in leaves})},'conditional_block':g,'wrapper':wrapper,'semantic_bytes':[{'rva':r,'bytes':read(r,n).hex()} for r,n in [(0x14c2225,38),(0x14c22e3,13),(0x14c2414,65),(0x15b40eb,46)]],'direct_calls':[{'site':0x14c2450,'target':0x15b40a0},{'site':0x15b410e,'target':0x5c6440}],'conclusions':{'all_17_paths_observed_runtime':False,'module_walk_interpretation':'consistent with x64 PEB/Ldr/list-style accesses; not a verified runtime module enumeration','exe_slot_writer_found':False,'code_preparation_proven':False,'bios_read_proven':False,'hardware_send_3724_proven':False,'next_callee_semantics':'unresolved'},'limitations':['Dispatcher coverage is only the first dispatch, not the full function or loop recovery','Symbolic entry global is arbitrary DWORD; satisfiable paths are not observed runtime paths','PEB-like block follows only the explicit disk-value scenario and non-equal list branch','No runtime structure contents, module identities, API names, or code-write targets established','Normal valid memory and stack accesses; exceptions, code mutation and nonlocal transfer not modeled','No input PE execution, patching, attachment, injection, or network test']}
 out.mkdir(parents=True,exist_ok=True);(out/'helper-proof.json').write_text(json.dumps(report,indent=2)+'\n')
 for name,body in [('conditional-initial-block',g),('wrapper',wrapper)]:
  lines=['; STATIC ONLY: '+body['condition']];annotations={r['rva']:r['reason'] for r in body['rules']}
  for node in body['nodes']:
   a=node['rva'];lines.append(f"{a:08x} {node['bytes']:32} {node['mnemonic']} {node['operands']}"+(' ; '+annotations[a] if a in annotations else ''))
  (out/(name+'.asm')).write_text('\n'.join(lines)+'\n')
 print(json.dumps({'paths':len(leaves),'distinct_frontiers':report['dispatcher']['distinct_frontiers'],'solver_unknown':len(unknown),'branch_checks':len(checks),'disk_only_frontier':hex(disk_leaves[0]['rva']),'conditional_block_instructions':len(g['nodes']),'wrapper_instructions':len(wrapper['nodes'])}))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args();run(a.input,a.out_dir)
