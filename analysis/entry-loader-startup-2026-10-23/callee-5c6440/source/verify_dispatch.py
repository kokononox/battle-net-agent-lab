"""Manual opcode/path verification; no Capstone or pefile; same Z3 solver."""
import argparse,copy,hashlib,json,struct
from pathlib import Path
from pe_manual import PE
from z3 import *
def verify(r,p):
 assert r['schema']=='wlab-callee-dispatch-1'
 assert r['module_sha256']==hashlib.sha256(p.b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
 entry=p.read(0x5c647d,39)
 assert entry.hex()=='448b0de8cdb501458d918ce905464181f212c19e9d4501c94529ca4181c243df0f904489542444'
 x=BitVec('independent_x',32);r9=x;r10=r9+0x4605e98c;r10=r10^0x9d9ec112;r9=r9+r9;r10=r10-r9;state=r10+0x900fdf43
 global_rva=0x5c6484+struct.unpack('<i',p.read(0x5c6480,4))[0];disk=p.u(global_rva,'<I')
 assert (r['global_rva'],r['disk'],r['disk_state'])==(global_rva,disk,simplify(substitute(state,(x,BitVecVal(disk,32)))).as_long())
 assert r['runtime_global_invariant'] is False
 for node in r['nodes']:assert p.read(node['rva'],len(bytes.fromhex(node['bytes']))).hex()==node['bytes']
 def solve(q):
  s=Solver();s.set(timeout=15000);s.add(q);v=s.check();assert v in (sat,unsat);return v
 names={0x8e:'jle',0x8f:'jg',0x8c:'jl',0x8d:'jge',0x84:'je',0x85:'jne',0x7e:'jle',0x7f:'jg',0x7c:'jl',0x7d:'jge',0x74:'je',0x75:'jne'}
 formulas=[]
 for l in r['leaves']:
  path=l['path'];assert path[0]==0x5c6564 and len(path)==len(set(path)) and path[-1]==l['rva'];pc=[];last=None
  for k,a in enumerate(path[:-1]):
   raw=p.read(a,8);nxt=path[k+1]
   if raw[:5]==bytes.fromhex('448b6c2444'):assert nxt==a+5
   elif raw[:3]==bytes.fromhex('4181fd'):last=struct.unpack('<I',raw[3:7])[0];assert nxt==a+7
   elif raw[0]==0xe9:assert nxt==a+5+struct.unpack('<i',raw[1:5])[0]
   else:
    near=raw[0]==0x0f;code=raw[1] if near else raw[0];m=names[code];n=a+(6 if near else 2);target=n+struct.unpack('<i' if near else '<b',raw[2:6] if near else raw[1:2])[0]
    assert nxt in (target,n) and target!=n and last is not None
    term={'jle':lambda:state<=last,'jg':lambda:state>last,'jl':lambda:state<last,'jge':lambda:state>=last,'je':lambda:state==last,'jne':lambda:state!=last}[m]()
    pc.append(term if nxt==target else Not(term))
  q=And(*pc);assert solve(q)==sat;assert is_true(simplify(substitute(q,(x,BitVecVal(l['witness'],32)))))
  assert l['disk_match']==is_true(simplify(substitute(q,(x,BitVecVal(disk,32)))))
  formulas.append(q)
 assert len(formulas)==17 and len({l['rva'] for l in r['leaves']})==17
 assert solve(Not(Or(*formulas)))==unsat
 for k,a in enumerate(formulas):
  for b in formulas[:k]:assert solve(And(a,b))==unsat
 assert r['coverage']=='unsat for uncovered DWORD' and r['pairwise_disjoint'] is True
 return {'manual_opcode_paths':'passed','independent_expression_and_coverage':'passed; same Z3 solver','paths':17,'distinct_frontiers':17,'uncovered_DWORD':'unsat','pairwise_overlap':'unsat','runtime_observed':False}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--report',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args();assert a.out.resolve()!=a.input.resolve(), "Output must not replace input";p=PE(a.input);r=json.loads(a.report.read_text());result=verify(r,p)
 tests=[]
 for label,fn in [('deleted_path',lambda q:q['leaves'].pop()),('changed_global',lambda q:q.__setitem__('global_rva',q['global_rva']+4)),('wrong_witness',lambda q:q['leaves'][0].__setitem__('witness',0))]:
  q=copy.deepcopy(r);fn(q)
  try:verify(q,p)
  except AssertionError:tests.append({'mutation':label,'rejected':True})
  else:raise AssertionError('mutation accepted '+label)
 result['mutation_tests']=tests;a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
