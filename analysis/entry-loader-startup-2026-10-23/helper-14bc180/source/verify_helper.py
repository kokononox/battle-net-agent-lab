"""Independent byte-level CFG verifier. Uses manual PE parsing and separate BV model."""
import argparse,copy,hashlib,json,random,struct
from pathlib import Path
from pe_manual import PE
from z3 import BitVec,Solver,Not,Or,And,BitVecVal,simplify,substitute,sat,unsat
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'

def verify(r,p):
 assert r['schema']=='wlab-helper-review-1' and r['module_sha256']==PIN==hashlib.sha256(p.b).hexdigest()
 f=r['function'];assert (f['start'],f['end'])==(0x14bc180,0x14c39bd)
 assert hashlib.sha256(p.read(f['start'],f['end']-f['start'])).hexdigest()==f['raw_sha256']
 assert p.read(f['start'],len(bytes.fromhex(f['entry_bytes']))).hex()==f['entry_bytes']
 # Independently lock translated arithmetic instructions; do not trust report's formula.
 spans={0x14bc1ad:'8b053d87ca00b9c91cbf6129c131c105a289b68c29c129c181c1a3ccf768894c244c',0x14bc1da:'e9d1000000',0x14c2225:'65488b042560000000488b4018488d481048898c2460030000488b40104839c80f84ed150000',0x14c2331:'0c008aed713d',0x14c237a:'7b367a4a',0x14c23b2:'7b08',0x14c23bc:'7b16',0x14c23c8:'7a0a',0x14c23d4:'a8e1c0ff007128',0x14c2403:'90710e',0x15b40a0:'4883ec384c89c04c8b4c2468733b86ff722b',0x15b40dd:'720c',0x15b40e9:'7300'}
 for a,h in spans.items():assert p.read(a,len(bytes.fromhex(h))).hex()==h
 d,size=p.dirs[3];assert any(struct.unpack('<II',p.read(a,8))==(f['start'],f['end']) for a in range(d,d+size,12))
 x=BitVec('independent_input',32);eax=x;ecx=BitVecVal(0x61bf1cc9,32);ecx=ecx-eax;ecx=ecx^eax;eax=eax+0x8cb689a2;ecx=ecx-eax;ecx=ecx-eax;ecx=ecx+0x68f7cca3;state=ecx
 def solve(q):
  s=Solver();s.set(timeout=10000);s.add(q);v=s.check();assert v in (sat,unsat),'solver unknown';return v
 assert solve((state&1)!=0)==unsat
 names={0x8f:'jg',0x8d:'jge',0x8c:'jl',0x8e:'jle',0x84:'je',0x85:'jne'}
 def term(m,k):return {'jg':lambda:state>k,'jge':lambda:state>=k,'jl':lambda:state<k,'jle':lambda:state<=k,'je':lambda:state==k,'jne':lambda:state!=k}[m]()
 def path_certificate(leaf):
  a=0x14bc2b0;path=[];decisions=[];constraints=[];last=None
  for _ in range(100):
   assert a not in path;path.append(a);raw=p.read(a,6)
   if raw[:4]==bytes.fromhex('8b44244c'):a+=4;continue
   if raw[0]==0x3d:last=(a,struct.unpack('<I',raw[1:5])[0]);a+=5;continue
   if raw[0]==0xe9:a=a+5+struct.unpack('<i',raw[1:5])[0];continue
   if raw[0]==0x0f and raw[1] in names and last is not None:
    q=leaf['decisions'][len(decisions)];m=names[raw[1]];assert q['site']==a and q['cmp_site']==last[0] and q['constant']==last[1] and q['mnemonic']==m
    pred=term(m,last[1]);constraints.append(pred if q['taken'] else Not(pred));decisions.append(q)
    a=a+6+(struct.unpack('<i',raw[2:6])[0] if q['taken'] else 0);continue
   assert a==leaf['rva'] and path==leaf['path'] and decisions==leaf['decisions'];return And(*constraints)
  raise AssertionError('path budget')
 ds=r['dispatcher'];assert ds['start']==0x14bc2b0 and ds['unknown']==[]
 assert ds['path_count']==len(ds['leaves'])==17 and ds['distinct_frontiers']==len({l['rva'] for l in ds['leaves']})==16
 formulas=[]
 for leaf in ds['leaves']:
  pc=path_certificate(leaf);formulas.append(pc);assert solve(pc)==sat
  w=leaf['witness_x'];assert str(simplify(substitute(pc,(x,BitVecVal(w,32)))))=='True'
  assert simplify(substitute(state,(x,BitVecVal(w,32)))).as_long()==leaf['witness_state']
 # Completeness is checked globally, independently of producer's queue/pruning.
 assert solve(Not(Or(*formulas)))==unsat
 for i in range(len(formulas)):
  for j in range(i):assert solve(And(formulas[i],formulas[j]))==unsat
 assert len(ds['branch_checks'])==100
 for check in ds['branch_checks']:
  terms=[]
  for q in check['path_decisions']:
   raw=p.read(q['site'],6);assert raw[0]==0x0f and names[raw[1]]==q['mnemonic']
   cmp=p.read(q['cmp_site'],5);assert cmp[0]==0x3d and struct.unpack('<I',cmp[1:])[0]==q['constant']
   v=term(q['mnemonic'],q['constant']);terms.append(v if q['taken'] else Not(v))
  assert str(solve(And(*terms)))==check['result']
 for node in ds['nodes']:assert p.read(node['rva'],len(bytes.fromhex(node['bytes']))).hex()==node['bytes']
 gi=r['initial_global'];a=0x14bc1b3+struct.unpack('<i',p.read(0x14bc1af,4))[0];value=p.u(a,'<I')
 assert gi=={'rva':a,'disk_u32':value,'disk_state':simplify(substitute(state,(x,BitVecVal(value,32)))).as_long(),'disk_only_frontier':0x14c2225,'runtime_invariant':False}
 matching=[leaf for leaf,pc in zip(ds['leaves'],formulas) if str(simplify(substitute(pc,(x,BitVecVal(value,32)))))=='True'];assert len(matching)==1 and matching[0]['rva']==0x14c2225
 def graph(g,start,stop,taken,free):
  assert (g['start'],g['stop_call'])==(start,stop)
  assert [(q['rva'],q['decision']) for q in g['rules']]==[(a,'taken') for a in sorted(taken)]
  nodes={n['rva']:n for n in g['nodes']};es={e['from']:e['to'] for e in g['edges']};occ=set()
  for a,node in nodes.items():
   b=bytes.fromhex(node['bytes']);assert p.read(a,len(b))==b;span=set(range(a,a+len(b)));assert not occ&span;occ|=span;n=a+len(b)
   if a==stop:succ=[];assert b[0]==0xe8
   elif len(b)==2 and 0x70<=b[0]<=0x7f:
    dest=n+struct.unpack('<b',b[1:])[0];assert a in taken|free;succ=[dest] if a in taken else [dest,n]
   elif len(b)==6 and b[0]==0x0f and 0x80<=b[1]<=0x8f:
    dest=n+struct.unpack('<i',b[2:])[0];assert a in taken|free;succ=[dest] if a in taken else [dest,n]
   else:succ=[n];assert b[0] not in [0xc3,0xe8,0xe9,0xeb]
   assert es[a]==succ
  reached=set()
  def walk(a,stack=frozenset()):
   assert a in nodes and a not in stack;reached.add(a)
   for v in es[a]:walk(v,stack|{a})
  walk(start);assert reached==set(nodes)
  def must(a):return a==stop or bool(es[a]) and all(must(v) for v in es[a])
  assert must(start)
  return len(nodes)
 assert r['conditional_block']['condition']=='Initial global equals its disk value; pointer comparison at 0x14C2242 is not equal; valid ordinary reads and unchanged code'
 assert r['wrapper']['condition']=='Conditional on reaching this wrapper; either CF after stack subtraction is allowed'
 n1=graph(r['conditional_block'],0x14c224b,0x14c2450,{0x14c2335,0x14c237c,0x14c23b2,0x14c23bc,0x14c23c8,0x14c23d9,0x14c2404},{0x14c237a})
 assert r['conditional_block']['unresolved_pointer_branch']=={'rva':0x14c2245,'equal_target':0x14c3838,'not_equal_target':0x14c224b}
 n2=graph(r['wrapper'],0x15b40a0,0x15b410e,{0x15b40b0,0x15b40dd,0x15b40e9},{0x15b40ac})
 assert r['direct_calls']==[{'site':0x14c2450,'target':0x15b40a0},{'site':0x15b410e,'target':0x5c6440}]
 for q in r['direct_calls']:
  raw=p.read(q['site'],5);assert raw[0]==0xe8 and q['site']+5+struct.unpack('<i',raw[1:])[0]==q['target']
 for q in r['semantic_bytes']:assert p.read(q['rva'],len(bytes.fromhex(q['bytes']))).hex()==q['bytes']
 assert r['conclusions']['all_17_paths_observed_runtime'] is False
 for name in ['exe_slot_writer_found','code_preparation_proven','bios_read_proven','hardware_send_3724_proven']:assert r['conclusions'][name] is False
 return {'independent_pe_and_relative_targets':'passed','independent_bv_coverage':'unsat for uncovered input','disjoint_leaf_paths':'passed','state_parity':'always even','first_dispatch_paths':17,'distinct_frontiers':16,'producer_branch_checks_rechecked':100,'solver_unknown':0,'conditional_block_instructions':n1,'wrapper_instructions':n2,'both_precall_graphs_must_hit':'passed','input_PE_executed':False}

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--report',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args();p=PE(a.input);r=json.loads(a.report.read_text());result=verify(r,p)
 mutants=[('removed_scenario_condition',lambda q:q['conditional_block'].__setitem__('condition','unconditional observed execution')),('changed_callee',lambda q:q['direct_calls'][1].__setitem__('target',0x5c6441)),('assumed_runtime_global',lambda q:q['initial_global'].__setitem__('runtime_invariant',True)),('deleted_dispatch_path',lambda q:q['dispatcher']['leaves'].pop()),('flipped_branch',lambda q:q['dispatcher']['leaves'][0]['decisions'][0].__setitem__('taken',not q['dispatcher']['leaves'][0]['decisions'][0]['taken'])),('changed_instruction',lambda q:q['wrapper']['nodes'][0].__setitem__('bytes','90')),('claimed_send',lambda q:q['conclusions'].__setitem__('hardware_send_3724_proven',True)),('removed_precall_edge',lambda q:q['conditional_block']['edges'][0].__setitem__('to',[]))]
 tests=[]
 for label,mutate in mutants:
  bad=copy.deepcopy(r);mutate(bad)
  try:verify(bad,p)
  except (AssertionError,KeyError,ValueError,IndexError):tests.append({'mutation':label,'rejected':True})
  else:raise AssertionError('mutation accepted: '+label)
 result['mutation_tests']=tests;a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
