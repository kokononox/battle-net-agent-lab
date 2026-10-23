"""Two bounded static fragments; never crosses or invents behavior of opaque call."""
import sys,json,struct,hashlib
from pathlib import Path
import pefile
from capstone import *
from capstone.x86 import *
from z3 import *
def run(inp,phase):
 b=inp.read_bytes();assert hashlib.sha256(b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';p=pefile.PE(data=b);cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
 RSP=0x1000000008; regs={};mem={};events=[];trace=[];globs={};branches=[];calls=[];external_writes=[];returns=[]
 alias={}
 for root,als in [('rax',['rax','eax','ax','al','ah']),('rbx',['rbx','ebx','bx','bl','bh']),('rcx',['rcx','ecx','cx','cl','ch']),('rdx',['rdx','edx','dx','dl','dh']),('rsi',['rsi','esi','si','sil']),('rdi',['rdi','edi','di','dil']),('rbp',['rbp','ebp','bp','bpl']),('rsp',['rsp','esp','sp','spl'])]+[(f'r{n}',[f'r{n}',f'r{n}d',f'r{n}w',f'r{n}b']) for n in range(8,16)]:
  for k,a in enumerate(als):alias[a]=(root,[64,32,16,8,8][k],8 if k==4 else 0)
  regs[root]=BitVec('entry_'+root,64)
 regs['rsp']=BitVecVal(RSP,64)
 def simp(x):return simplify(x)
 def const(x):
  x=simp(x)
  if is_bv_value(x):return x.as_long()
  raise ValueError('symbolic address '+str(x))
 def rr(name):
  root,w,shift=alias[name];return Extract(shift+w-1,shift,regs[root]) if w<64 else regs[root]
 def wr(name,v):
  root,w,shift=alias[name];v=simp(v)
  if v.size()!=w:v=Extract(w-1,0,v) if v.size()>w else ZeroExt(w-v.size(),v)
  if w==64:regs[root]=v
  elif w==32:regs[root]=ZeroExt(32,v)
  elif shift:regs[root]=Concat(Extract(63,16,regs[root]),v,Extract(7,0,regs[root]))
  else:regs[root]=Concat(Extract(63,w,regs[root]),v)
  regs[root]=simp(regs[root])
 def store(a,v,n):
  for k in range(n):mem[a+k]=Extract(k*8+7,k*8,v)
 def load(a,n):
  if RSP-0x1000<=a<RSP+0x100:
   if any(a+k not in mem for k in range(n)):raise ValueError('uninitialized stack '+hex(a))
   return simp(Concat(*[mem[a+k] for k in reversed(range(n))]))
  if 0<=a<0x3000000:
   raw=p.get_data(a,n);assert len(raw)==n;globs[(a,n)]=raw.hex();return BitVecVal(int.from_bytes(raw,'little'),n*8)
  raise ValueError('external memory '+hex(a))
 D,U,N,Q,P=[BitVec(k,64) for k in ['destination_base','source_base','unit_count','output_qword_pointer','control_dword_pointer']]
 regs.update(rcx=BitVecVal(0x17,64),rdx=Q,r8=P,r9=BitVecVal(0x10,64))
 store(RSP+0x28,D,8);store(RSP+0x30,U,8);store(RSP+0x38,BitVecVal(0x2f,64),8);store(RSP+0x40,N,8)
 if phase=='suffix':
  frame=RSP-0x108;regs.update(rsp=BitVecVal(frame,64),rbx=D,rbp=~D,r13=U,rsi=U+2*N,r14=BitVecVal(frame+0xb0,64),r15=D+0x100,r12=BitVecVal(frame+0xa0,64),rdi=P,rax=BitVec('opaque_return_rax',64))
  store(frame+0xa0,BitVec('cursor_after_opaque_call',64),8);store(frame+0x50,Q,8)
  # Define a snapshot, not a summary of the opaque call's behavior.
  cookie=BitVecVal(int.from_bytes(p.get_data(0x20d01c0,8),'little'),64)
  store(frame+0xc0,cookie^BitVecVal(frame,64),8)
  for k,name in enumerate(['rbx','rbp','rdi','rsi','r12','r13','r14','r15']):store(frame+0xc8+k*8,BitVec('saved_'+name,64),8)
 
 def addr(i,o):
  m=o.mem;v=BitVecVal(m.disp%(1<<64),64)
  if m.base: v=v+(BitVecVal(i.address+i.size,64) if i.reg_name(m.base)=='rip' else rr(i.reg_name(m.base)))
  if m.index:v=v+rr(i.reg_name(m.index))*m.scale
  return simp(v)
 def val(i,o):
  if o.type==X86_OP_REG:return rr(i.reg_name(o.reg))
  if o.type==X86_OP_IMM:return BitVecVal(o.imm%(1<<(o.size*8)),o.size*8)
  return load(const(addr(i,o)),o.size)
 def put(i,o,v):
  if o.type==X86_OP_REG:wr(i.reg_name(o.reg),v)
  else:
   address=addr(i,o)
   if is_true(simplify(address==Q)):
    external_writes.append({'site':i.address,'pointer':'output_qword_pointer','size':o.size,'value_smt2':simplify(v).sexpr()});return
   a=const(address);assert RSP-0x1000<=a<RSP+0x100,'external write';store(a,v,o.size)
 flags={}
 def fcommon(v):
  w=v.size();flags.update(ZF=v==0,SF=Extract(w-1,w-1,v)==1,PF=(Extract(0,0,v)^Extract(1,1,v)^Extract(2,2,v)^Extract(3,3,v)^Extract(4,4,v)^Extract(5,5,v)^Extract(6,6,v)^Extract(7,7,v))==0)
 def resolve(q):
  q=simp(q)
  if is_true(q):return True
  if is_false(q):return False
  s=Solver();s.set(timeout=10000);s.add(Not(q));a=s.check()
  if a==unsat:return True
  s=Solver();s.set(timeout=10000);s.add(q);a=s.check()
  if a==unsat:return False
  raise ValueError('symbolic branch '+str(q))
 ip=0x683780 if phase=='prefix' else 0x683ca8
 for count in range(4000):
  i=next(cs.disasm(p.get_data(ip,15),ip,count=1));trace.append({'rva':ip,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});n=ip+i.size;op=i.operands;m=i.mnemonic
  try:
   if m=='push':v=val(i,op[0]);regs['rsp']=simp(regs['rsp']-8);store(const(regs['rsp']),v,8)
   elif m=='pop':v=load(const(regs['rsp']),8);put(i,op[0],v);regs['rsp']=simp(regs['rsp']+8)
   elif m=='mov':put(i,op[0],val(i,op[1]))
   elif m=='movzx':put(i,op[0],ZeroExt(op[0].size*8-op[1].size*8,val(i,op[1])))
   elif m=='lea':v=addr(i,op[1]);put(i,op[0],v)
   elif m in ('add','sub','xor','and','or','cmp','test'):
    a,c=val(i,op[0]),val(i,op[1]);w=a.size();c=Extract(w-1,0,c) if c.size()>w else SignExt(w-c.size(),c) if c.size()<w else c
    if m in ('add','sub','cmp'):
     v=simp(a+c if m=='add' else a-c);sa,sc,sv=[Extract(w-1,w-1,q) for q in (a,c,v)]
     flags['CF']=ULT(v,a) if m=='add' else ULT(a,c);flags['OF']=And(sa==sc,sa!=sv) if m=='add' else And(sa!=sc,sa!=sv)
    else:v=simp({'xor':lambda:a^c,'and':lambda:a&c,'test':lambda:a&c,'or':lambda:a|c}[m]());flags['CF']=BoolVal(False);flags['OF']=BoolVal(False)
    fcommon(v)
    if m not in ('cmp','test'):put(i,op[0],v)
   elif m in ('inc','dec'):
    a=val(i,op[0]);v=simp(a+(1 if m=='inc' else -1));flags['OF']=a==((1<<(a.size()-1))-1 if m=='inc' else (1<<(a.size()-1)));fcommon(v);put(i,op[0],v)
   elif m=='imul':
    a,c=val(i,op[1]),val(i,op[2]);w=op[0].size*8
    if c.size()!=w:c=SignExt(w-c.size(),c) if c.size()<w else Extract(w-1,0,c)
    full=SignExt(w,a)*SignExt(w,c);v=Extract(w-1,0,full);put(i,op[0],v);overflow=full!=SignExt(w,v);flags={'CF':overflow,'OF':overflow}
   elif m=='not':put(i,op[0],~val(i,op[0]))
   elif m=='neg':
    a=val(i,op[0]);v=simp(-a);flags['CF']=a!=0;flags['OF']=a==1<<(a.size()-1);fcommon(v);put(i,op[0],v)
   elif m in ('sar','shr','shl'):
    a=val(i,op[0]);c=const(val(i,op[1])) & (63 if a.size()==64 else 31)
    if c:
     raise ValueError('nonzero shift unsupported')
   elif m=='clc':flags['CF']=BoolVal(False)
   elif m=='stc':flags['CF']=BoolVal(True)
   elif m=='xchg':a,c=val(i,op[0]),val(i,op[1]);put(i,op[0],c);put(i,op[1],a)
   elif m in ('nop','endbr64'):pass
   elif m=='jmp':n=op[0].imm
   elif m.startswith('j'):
    z,s,o,c,pf=[flags.get(q,Bool(q)) for q in ('ZF','SF','OF','CF','PF')]
    q={'je':z,'jne':Not(z),'jg':And(Not(z),s==o),'jge':s==o,'jl':s!=o,'jle':Or(z,s!=o),'ja':And(Not(c),Not(z)),'jae':Not(c),'jb':c,'jbe':Or(c,z),'jo':o,'jno':Not(o),'jp':pf,'jnp':Not(pf)}[m];taken=resolve(q);branches.append({'site':ip,'taken':taken});n=op[0].imm if taken else n
   elif m=='ret':
    if returns:
     n=returns.pop();assert const(load(const(regs['rsp']),8))==n;regs['rsp']=simplify(regs['rsp']+8)
    else:events.append({'kind':'return','rax':str(simp(regs['rax']))});break
   elif m=='call':
    target=op[0].imm
    calls.append({'site':i.address,'target':target,'registers':{k:str(simplify(regs[k])) for k in ['rcx','rdx','r8','r9']},'stack_args':{hex(k):str(load(const(regs['rsp'])+k,8)) for k in [0x20,0x28]}})
    if target in (0x1948090,0xe83570):
     returns.append(n);regs['rsp']=simplify(regs['rsp']-8);store(const(regs['rsp']),BitVecVal(n,64),8);n=target
    else:events.append({'kind':'opaque_call_boundary','site':i.address,'target':target});break
   else:raise ValueError('unsupported '+m)
  except Exception as e:
   events.append({'kind':'frontier','site':ip,'reason':str(e)});break
  ip=n
 else:events.append({'kind':'budget'})
 frame=RSP-0x108
 result={'phase':phase,'trace':trace,'global_reads':[{'rva':a,'size':n,'bytes':h} for (a,n),h in sorted(globs.items())],'branches':branches,'events':events,'calls':calls,'external_writes':external_writes,'final_registers':{k:str(simp(v)) for k,v in regs.items()},'locals':{hex(k):str(load(frame+k,8)) if all(frame+k+i in mem for i in range(8)) else 'uninitialized in this fragment' for k in [0x38,0x40,0x50,0x98,0xa0,0xa8,0xb0,0xb8]}}
 def prove_equal(a,b):
  sol=Solver();sol.set(timeout=5000);sol.add(a!=b);return str(sol.check())
 if phase=='prefix':
  result['span_proofs']={name:prove_equal(load(frame+off,8),expected) for name,off,expected in [('destination_begin',0xa0,D),('destination_end',0xa8,D+256),('source_begin',0xb0,U),('source_end',0xb8,U+2*N)]}
 if phase=='suffix' and external_writes:
  A=BitVec('cursor_after_opaque_call',64);B=D
  terms={0x60:11*(~A&B),0x68:11*(A|B),0x70:A^B,0x78:A^B,0x80:~B&A,0x88:9*(~B&A),0x90:A&B}
  result['intermediate_proofs']={hex(off):prove_equal(load(frame+off,8),value) for off,value in terms.items()}
  # The last block's linear formula is separately locked to opcodes in the verifier.
  u,v,w=BitVecs('common only_A only_B',64)
  compact=-11*u-9*v-(v+w)+11*(u+v+w)-11*w
  result['partition_ring_proof']=prove_equal(compact,(u+v)-(u+w))
  result['partition_truth_table']=[{'a':a,'b':b,'common':a&b,'only_A':a&(1-b),'only_B':(1-a)&b} for a in [0,1] for b in [0,1]]
  result['output_identity']='cursor_after_opaque_call - destination_base (mod 2^64)'
 result.update(schema='wlab-span-adapter-'+phase+'-1',module_sha256=hashlib.sha256(b).hexdigest(),synthetic_entry_rsp=RSP,assumptions=['All recorded module reads equal their disk bytes at each read; instruction bytes unchanged','Valid stack, ordinary memory and nonaliasing analysis regions; no exceptions, nonlocal control flow or asynchronous code mutation','The prefix ends before the opaque call; the suffix is a separate snapshot, NOT an inferred postcondition of that call'],conclusions={'runtime_observed':False,'opaque_call_implemented_or_summarized':False,'source_content_or_encoding_proven':False,'hardware_read_proven':False,'hardware_send_3724_proven':False,'exe_slot_writer_found':False,'actual_output_bytes_proven':False})
 if phase=='prefix':
  assert events==[{'kind':'opaque_call_boundary','site':0x683ca3,'target':0x6995d0}]
  assert all(v=='unsat' for v in result['span_proofs'].values())
  result['semantic_contract']={'destination_span':['D','D + 256 (mod 2^64)'],'source_span':['U','U + 2*N (mod 2^64)'],'opaque_target':'0x6995D0','opaque_call_registers':{'RCX':'0x63','RDX':'pointer to local destination span (16 bytes)','R8':'pointer to local source span (16 bytes)','R9':'0x63'},'opaque_stack_args':{'5':'incoming control DWORD pointer','6':'0xA'},'control_pointer_dereferenced_in_prefix':False,'source_and_destination_contents_read_in_prefix':False}
 else:
  assert events==[{'kind':'return','rax':'Concat(0, Extract(31, 0, opaque_return_rax))'}]
  assert len(external_writes)==1 and external_writes[0]['site']==0x683cdd and external_writes[0]['size']==8
  assert all(v=='unsat' for v in result['intermediate_proofs'].values()) and result['partition_ring_proof']=='unsat'
  result['snapshot']={'entry_instruction':'0x683CA8','frame':'entry RSP - 0x108','RBX':'D','RBP':'~D','frame+0xA0':'arbitrary A (cursor_after_opaque_call)','frame+0x50':'arbitrary Q (output_qword_pointer)','RAX':'arbitrary opaque return','cookie':'matching recorded cookie for normal epilogue','saved_nonvolatile_registers':'arbitrary saved values for epilogue'}
  result['semantic_contract']={'write_site':'0x683CDD','write_size':8,'destination':'Q','value':'A - D (mod 2^64)','return_low32':'low32 of opaque return','does_not_establish':'A is advanced correctly, output is in bounds, or bytes were actually produced by the opaque call'}
 return result

if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args();a.out_dir.mkdir(parents=True,exist_ok=True)
 for phase in ['prefix','suffix']:
  out=a.out_dir/(phase+'-proof.json');assert out.resolve()!=a.input.resolve()
  result=run(a.input,phase);out.write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({'phase':phase,'instructions':len(result['trace']),'event':result['events'],'proofs':result.get('span_proofs',result.get('intermediate_proofs'))}))
