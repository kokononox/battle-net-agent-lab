"""Offline symbolic first dispatcher of loader ordinal 1; not target execution."""
from pathlib import Path
from pe_manual import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from z3 import *
import json,hashlib,struct
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));h=hashlib.sha256(p.b).hexdigest();assert h=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
m=Cs(CS_ARCH_X86,CS_MODE_64)
def dec(a):return next(m.disasm(p.read(a,15),a,count=1))
# Translate actual initial straight-line instructions; stop rather than guess.
x=BitVec('global_u32',32);regs={};nodes={};a=0x22eff6
while a<0x22f03c:
 i=dec(a);nodes[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str};d,s=i.op_str.split(', ',1)
 if i.mnemonic=='mov' and s.startswith('dword ptr [rip + '):
  g=a+i.size+int(s[len('dword ptr [rip + '):-1],0);regs[d]=x
 elif i.mnemonic=='mov':regs[d]=regs[s]
 elif i.mnemonic=='lea':
  import re
  q=re.fullmatch(r'\[(\w+) \+ (0x[0-9a-f]+)\]',s);assert q,s
  alias={'rax':'eax','rdx':'edx','rcx':'ecx'};regs[d]=regs[alias.get(q[1],q[1])]+int(q[2],0)
 elif i.mnemonic in ['add','sub','xor']:
  v=regs[s] if s in regs else int(s,0)
  regs[d]={'add':lambda:regs[d]+v,'sub':lambda:regs[d]-v,'xor':lambda:regs[d]^v}[i.mnemonic]()
 else:raise AssertionError((a,i.mnemonic,i.op_str))
 a+=i.size
state=regs['ecx'];disk=p.u(g,'<I');todo=[(0x22f0e0,[],[],None)];leaves=[];queries=[]
while todo:
 a,conds,path,last=todo.pop()
 for step in range(100):
  i=dec(a);nodes[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str};path=path+[a];n=a+i.size
  if i.mnemonic=='mov' and i.op_str=='r10d, dword ptr [rsp + 0xc]':a=n;continue
  if i.mnemonic=='cmp' and i.op_str.startswith('r10d, '):last=int(i.op_str.split(', ')[1],0);a=n;continue
  if i.mnemonic in ['je','jne','jg','jge','jl','jle']:
   q={'je':state==last,'jne':state!=last,'jg':state>last,'jge':state>=last,'jl':state<last,'jle':state<=last}[i.mnemonic]
   for taken,dst in [(True,int(i.op_str,16)),(False,n)]:
    c=q if taken else Not(q);s=Solver();s.set(timeout=15000);s.add(*(conds+[c]));r=s.check();queries.append(str(r))
    if r==sat:todo.append((dst,conds+[c],path,last))
    elif r!=unsat:raise RuntimeError('solver unknown; do not claim coverage')
   break
  formula=And(*conds);s=Solver();s.set(timeout=15000);s.add(formula);assert s.check()==sat;w=s.model().eval(x,model_completion=True).as_long()
  leaves.append({'rva':a,'path':path,'witness':w,'disk_matches':is_true(simplify(substitute(formula,(x,BitVecVal(disk,32))))),'condition':formula.sexpr()});break
 else:raise RuntimeError('step bound')
forms=[parse_smt2_string('(declare-fun global_u32 () (_ BitVec 32)) (assert '+l['condition']+')')[0] for l in leaves]
s=Solver();s.set(timeout=15000);s.add(Not(Or(*forms)));coverage=str(s.check());assert coverage=='unsat'
report={'module_sha256':h,'entry_rva':0x22eff0,'scope':'Only first dispatcher from imported ordinal 1. Invocation and runtime globals are not established. Frontier bodies are not analyzed. No input executable is run.','global_rva':g,'disk_global_u32':disk,'initial_state_smt':state.sexpr(),'leaves':leaves,'nodes':[nodes[a] for a in sorted(nodes)],'branch_query_results':queries,'uncovered_input_query':coverage,'claims':{'decryptor_identified':False,'key_recovered':False,'runtime_path_observed':False,'page_writer_identified':False,'hardware_send_proven':False}}
Path('/data/wlab-code-preparation-review/export-dispatch.json').write_text(json.dumps(report,indent=2))
print(json.dumps({'frontiers':[hex(l['rva']) for l in leaves],'disk_conditional_frontiers':[hex(l['rva']) for l in leaves if l['disk_matches']],'coverage':coverage,'queries':len(queries)}))
