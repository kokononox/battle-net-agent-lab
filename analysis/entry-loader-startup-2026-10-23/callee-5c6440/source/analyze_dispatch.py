"""First-dispatch coverage only, pinned build; static analysis."""
import sys
import pefile,struct,json
from capstone import *
from z3 import *
from pathlib import Path
import argparse,hashlib
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);args=ap.parse_args();assert args.out.resolve()!=args.input.resolve(), "Output must not replace input"
b=args.input.read_bytes();assert hashlib.sha256(b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';p=pefile.PE(data=b);cs=Cs(CS_ARCH_X86,CS_MODE_64)
def dec(r):return next(cs.disasm(p.get_data(r,15),r,count=1))
x=BitVec('x',32);state=((x+0x4605e98c)^0x9d9ec112)-2*x+0x900fdf43
rva=0x5c6484+struct.unpack('<i',p.get_data(0x5c6480,4))[0];disk=struct.unpack('<I',p.get_data(rva,4))[0];ds=simplify(substitute(state,(x,BitVecVal(disk,32)))).as_long()
todo=[(0x5c6564,[],[],None)];leaves=[];nodes={};formulas=[]
while todo:
 a,conds,path,last=todo.pop()
 for step in range(100):
  i=dec(a);nodes[a]={'rva':a,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};path=path+[a];n=a+i.size
  if i.mnemonic=='mov' and i.op_str=='r13d, dword ptr [rsp + 0x44]':a=n;continue
  if i.mnemonic=='cmp' and i.op_str.startswith('r13d, '):last=int(i.op_str.split(', ')[1],0);a=n;continue
  if i.mnemonic in ('je','jne','jg','jge','jl','jle'):
   q={'je':state==last,'jne':state!=last,'jg':state>last,'jge':state>=last,'jl':state<last,'jle':state<=last}[i.mnemonic]
   for taken,dst in [(True,int(i.op_str,16)),(False,n)]:
    cond=q if taken else Not(q);s=Solver();s.set(timeout=15000);s.add(*(conds+[cond]));r=s.check();assert r in (sat,unsat)
    if r==sat:todo.append((dst,conds+[cond],path,last))
   break
  s=Solver();s.add(*conds);assert s.check()==sat;w=s.model().eval(x,model_completion=True).as_long()
  formulas.append(And(*conds));leaves.append({'rva':a,'path':path,'witness':w,'disk_match':all(is_true(simplify(substitute(c,(x,BitVecVal(disk,32))))) for c in conds),'conditions':[c.sexpr() for c in conds]});break

s=Solver();s.set(timeout=15000);s.add(Not(Or(*formulas)));assert s.check()==unsat
for i,a in enumerate(formulas):
 for b_ in formulas[:i]:
  s=Solver();s.set(timeout=15000);s.add(a,b_);assert s.check()==unsat
result={'schema':'wlab-callee-dispatch-1','module_sha256':hashlib.sha256(b).hexdigest(),'global_rva':rva,'disk':disk,'disk_state':ds,'leaves':leaves,'nodes':list(nodes.values()),'coverage':'unsat for uncovered DWORD','pairwise_disjoint':True,'runtime_global_invariant':False,'scope':'First dispatch only; all symbolic DWORD inputs, not observed runtime paths'}
args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'paths':len(leaves),'distinct_frontiers':len({l['rva'] for l in leaves}),'disk_frontier':[hex(l['rva']) for l in leaves if l['disk_match']]}))
