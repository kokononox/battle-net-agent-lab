"""Bounded static overapproximation from pdata entries, NOT runtime reachability."""
from pathlib import Path
import json,hashlib,collections,itertools,functools
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import *
from pe_manual import PE
FLAGS=['CF','ZF','SF','OF','PF'];UNKNOWN=(None,)*5
INV={'je':'jne','jne':'je','jg':'jle','jle':'jg','jge':'jl','jl':'jge','ja':'jbe','jbe':'ja','jae':'jb','jb':'jae','js':'jns','jns':'js','jo':'jno','jno':'jo','jp':'jnp','jnp':'jp'}
def both(a,b):return False if a is False or b is False else True if a is True and b is True else None
def either(a,b):return True if a is True or b is True else False if a is False and b is False else None
def neg(x):return None if x is None else not x
def truth(op,st):
 cf,zf,sf,of,pf=st;eq=None if sf is None or of is None else sf==of
 return {'je':zf,'jne':neg(zf),'jb':cf,'jae':neg(cf),'jbe':either(cf,zf),'ja':both(neg(cf),neg(zf)),'js':sf,'jns':neg(sf),'jo':of,'jno':neg(of),'jp':pf,'jnp':neg(pf),'jl':neg(eq),'jge':eq,'jle':either(zf,neg(eq)),'jg':both(neg(zf),eq)}.get(op)
ALL_MASK=(1<<32)-1
CONCRETE=[tuple(bool(n&(1<<k)) for k in range(5)) for n in range(32)]
@functools.lru_cache(None)
def condition_mask(mnemonic):
 return sum(1<<n for n,st in enumerate(CONCRETE) if truth(mnemonic,st) is True)
def known_bits(mask):
 xs=[CONCRETE[n] for n in range(32) if mask&(1<<n)]
 return tuple(xs[0][k] if all(x[k]==xs[0][k] for x in xs) else None for k in range(5))
@functools.lru_cache(None)
def transfer_mask(mask,free,on,off):
 keep=31&~(free|on|off);options=[n for n in range(32) if n&~free==0];out=0
 for n in range(32):
  if mask&(1<<n):
   fixed=(n&keep)|on
   for v in options:out|=1<<(fixed|v)
 return out
def mask_transfer(i,mask):
 if i.mnemonic=='call':return ALL_MASK
 preserve={'mov','movabs','movzx','movsx','movsxd','lea','nop','xchg','push','pop','pushf','pushfd','pushfq','bswap','not','endbr64','rdtsc','rdtscp','cpuid'}
 integer_flags={'add','adc','sub','sbb','cmp','test','and','or','xor','inc','dec','neg','sal','shl','shr','sar','rol','ror','rcl','rcr','shld','shrd','imul','mul','div','idiv','bt','btc','btr','bts','bsf','bsr','lzcnt','tzcnt','popcnt','blsi','blsr','blsmsk','bzhi','adcx','adox','cmpxchg','cmpxchg8b','cmpxchg16b','xadd','stc','clc','cmc','cld','std','sahf','lahf','popf','popfd','popfq'}
 if i.mnemonic in preserve or i.mnemonic.startswith(('j','cmov','set')) or i.mnemonic.startswith('loop'):return mask
 # Never interpret x87/FPU-status metadata as integer EFLAGS. Unsupported
 # effects lose ALL flag knowledge, a conservative overapproximation.
 if i.mnemonic not in integer_flags:return ALL_MASK
 if i.mnemonic in ['sal','shl','shr','sar','rol','ror','rcl','rcr','shld','shrd'] and i.operands and i.operands[-1].type==X86_OP_IMM and i.operands[-1].imm==0:return mask
 if i.mnemonic in ['xor','sub','cmp'] and len(i.operands)==2 and all(x.type==X86_OP_REG for x in i.operands) and i.operands[0].reg==i.operands[1].reg:return 1<<18
 free=on=off=0
 for k,f in enumerate(FLAGS):
  if i.eflags&(globals().get('X86_EFLAGS_MODIFY_'+f,0)|globals().get('X86_EFLAGS_UNDEFINED_'+f,0)):free|=1<<k
  if i.eflags&globals().get('X86_EFLAGS_RESET_'+f,0):off|=1<<k
  if i.eflags&globals().get('X86_EFLAGS_SET_'+f,0):on|=1<<k
 free&=~(on|off);off&=~on
 return mask if not(free|on|off) else transfer_mask(1 if (free|on|off)==31 else mask,free,on,off)
def walk(read,start,end,cap=10000,wanted=()):
 md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;cache={};nodes={};states=set();todo=[(start,ALL_MASK)];escapes=set();bad=set();traps=set();indirect=set();pairs=set();folds=set();capped=False;parents={(start,ALL_MASK):None};found={}
 def dec(a):
  if not start<=a<end:return None
  if a not in cache:cache[a]=next(md.disasm(read(a,min(15,end-a)),a,count=1),None)
  return cache[a]
 while todo:
  a,st=todo.pop()
  if (a,st) in states:continue
  if len(states)>=cap:capped=True;break
  states.add((a,st))
  if not start<=a<end:escapes.add(a);continue
  i=dec(a)
  if i is None:bad.add(a);continue
  nodes[a]=i
  if a in wanted and a not in found:found[a]=(a,st)
  n=a+i.size;new=mask_transfer(i,st);succ=[];successor_states=None
  if i.mnemonic in INV:
   target=i.operands[0].imm;j=dec(n);bridge=None
   if j and ((j.mnemonic in ['sal','shl','shr','sar','rol','ror'] and j.operands[-1].type==X86_OP_IMM and j.operands[-1].imm==0 and j.operands[0].type==X86_OP_REG) or (j.mnemonic=='mov' and len(j.operands)==2 and all(op.type==X86_OP_REG for op in j.operands) and j.operands[0].reg==j.operands[1].reg)):
    bridge=j;j=dec(j.address+j.size)
   if j and j.mnemonic==INV[i.mnemonic] and j.operands[0].type==X86_OP_IMM and j.operands[0].imm==target:
    pairs.add((a,j.address,target));succ=[target]
   else:
    cm=condition_mask(i.mnemonic);tm=st&cm;fm=st&(ALL_MASK^cm)
    if not tm or not fm:folds.add((a,target,n,bool(tm)))
    successor_states=[]
    if tm:successor_states.append((target,tm))
    if fm:successor_states.append((n,fm))
  elif i.mnemonic=='jmp':
   if i.operands[0].type==X86_OP_IMM:succ=[i.operands[0].imm]
   else:indirect.add(a)
  elif i.group(CS_GRP_JUMP):
   if i.operands and i.operands[0].type==X86_OP_IMM:succ=[i.operands[0].imm,n]
   else:indirect.add(a)
  elif i.mnemonic in ['ret','retf','retfq']:pass
  elif i.mnemonic.startswith(('int','iret')) or i.mnemonic in ['ud0','ud1','ud2','hlt','syscall','sysenter','sysexit','sysret']:
   traps.add(a)
  else:succ=[n]
  for x,nextstate in (successor_states if successor_states is not None else [(x,new) for x in succ]):
   if wanted:parents.setdefault((x,nextstate),(a,st))
   todo.append((x,nextstate))
 occupied={};overlaps=set()
 for a,i in nodes.items():
  for x in range(a,a+i.size):
   if x in occupied and occupied[x]!=a:overlaps.add((occupied[x],a))
   occupied[x]=a
 closed=not (escapes or bad or traps or indirect or overlaps or capped)
 paths={}
 for target,key in found.items():
  path=[]
  while key is not None:
   a,st=key;i=nodes.get(a);path.append({'rva':a,'flags_in':list(known_bits(st)),'flags_mask_hex':hex(st),'asm':i.mnemonic+' '+i.op_str if i else 'unavailable','bytes':i.bytes.hex() if i else ''});key=parents[key]
  paths[str(target)]=list(reversed(path))
 return ({'witness_paths':paths} if wanted else {}) | {'begin':start,'end':end,'states_examined':len(states),'instruction_boundaries_examined':len(nodes),'normalized_complementary_pairs':len(pairs),'definite_flag_branch_decisions':len(folds),'bad_decode_rvas':sorted(bad),'outside_range_successors':sorted(escapes),'trap_or_system_transfer_rvas':sorted(traps),'indirect_jumps':sorted(indirect),'overlapping_instruction_pairs':[list(x) for x in sorted(overlaps)],'budget_exhausted':capped,'closed_under_stated_model':closed},nodes
if __name__=='__main__':
 D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));assert hashlib.sha256(p.b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
 d=json.loads((D/'reports/discovery.json').read_text());group=collections.defaultdict(list)
 for c in d['rip_syntactic_candidates']:
  if c['containing_function']:group[tuple(c['containing_function'])].append(c)
 rows=[];retained=[];excluded=[];unresolved=[]
 for (start,end),cs in sorted(group.items()):
  row,nodes=walk(p.read,start,end);row['syntactic_candidate_count']=len(cs);row['candidates_seen_on_explored_boundary']=[]
  for c in cs:
   i=nodes.get(c['rva']);seen=bool(i and i.bytes.hex()==c['bytes'])
   entry={**c,'function_closed_under_model':row['closed_under_stated_model']}
   if seen:row['candidates_seen_on_explored_boundary'].append(c['rva']);retained.append(entry)
   elif row['closed_under_stated_model']:excluded.append(entry)
   else:unresolved.append(entry)
  rows.append(row)
 out={'source_sha256':d['input_sha256'],'model':'Entry-only, ordinary successful instruction semantics; calls may return normally with unknown flags; no call-body traversal, exception edges or external mid-function entries. Uses Capstone flag metadata only for an explicit integer-instruction allowlist; other effects clobber flag knowledge. Definite same-register XOR/SUB/CMP complementary conditional-pair normalization and per-edge intersections over all 32 possible CF/ZF/SF/OF/PF combinations. Unchanged flags preserve correlations; arithmetic writes are conservatively overapproximated. Static OVERAPPROXIMATION, not actual execution.','functions':rows,'retained_syntactic_candidates':retained,'excluded_in_closed_model':excluded,'unresolved_in_incomplete_model':unresolved,'outside_pdata_candidates':[x for x in d['rip_syntactic_candidates'] if not x['containing_function']],'claims':{'eid_consumer_identified':False,'decryption_identified':False,'runtime_reachability_confirmed':False}}
 (D/'reports/reachability.json').write_text(json.dumps(out,indent=2)+'\n')
 print('Functions examined',len(rows),'closed models',sum(r['closed_under_stated_model'] for r in rows),'budget hits',sum(r['budget_exhausted'] for r in rows));print('Candidates retained',len(retained),'excluded within closed models',len(excluded),'unresolved',len(unresolved),'outside pdata',len(out['outside_pdata_candidates']));print('RETAINED',json.dumps(retained[:30]));print('Boundary count',sum(r['instruction_boundaries_examined'] for r in rows))
