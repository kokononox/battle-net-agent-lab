"""Bounded static bit-vector interpreter; never loads or executes an input PE."""
import sys
from capstone import *
from capstone.x86 import *
import pefile,json,struct
from pathlib import Path
from z3 import *
import argparse,hashlib
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);args=ap.parse_args();assert args.out.resolve()!=args.input.resolve(), "Output must not replace input"
b=args.input.read_bytes();assert hashlib.sha256(b).hexdigest()=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';p=pefile.PE(data=b);cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
RSP=0x1000000008; regs={};mem={};events=[];trace=[];globs={};branches=[]
alias={}
for root,als in [('rax',['rax','eax','ax','al','ah']),('rbx',['rbx','ebx','bx','bl','bh']),('rcx',['rcx','ecx','cx','cl','ch']),('rdx',['rdx','edx','dx','dl','dh']),('rsi',['rsi','esi','si','sil']),('rdi',['rdi','edi','di','dil']),('rbp',['rbp','ebp','bp','bpl']),('rsp',['rsp','esp','sp','spl'])]+[(f'r{n}',[f'r{n}',f'r{n}d',f'r{n}w',f'r{n}b']) for n in range(8,16)]:
 for k,a in enumerate(als):alias[a]=(root,[64,32,16,8,8][k],8 if k==4 else 0)
 regs[root]=BitVec('entry_'+root,64)
regs['rsp']=BitVecVal(RSP,64);regs['r8']=BitVecVal(0x46,64)
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
store(RSP+0x28,BitVecVal(0x21,64),8);store(RSP+0x30,BitVecVal(0x1c,64),8);store(RSP+0x38,BitVec('arg7',64),8)
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
  a=const(addr(i,o));assert RSP-0x1000<=a<RSP+0x100,'external write';store(a,v,o.size)
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
ip=0x5c6440
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
  elif m=='ret':events.append({'kind':'return','rax':str(simp(regs['rax']))});break
  elif m=='call':raise ValueError('call frontier '+i.op_str)
  else:raise ValueError('unsupported '+m)
 except Exception as e:
  events.append({'kind':'frontier','site':ip,'reason':str(e)});break
 ip=n
else:events.append({'kind':'budget'})
result={'trace':trace,'global_reads':[{'rva':a,'size':n,'bytes':h} for (a,n),h in sorted(globs.items())],'branches':branches,'events':events,'final_registers':{k:str(simp(v)) for k,v in regs.items()},'stack_at_call':{hex(o):str(load(const(regs['rsp'])+o,8 if o in [0x20,0x28,0x30,0x38] else 4)) for o in [0x20,0x28,0x30,0x38,0x4c,0x48,0x50,0x54,0xcc]}}

assert events==[{'kind':'frontier','site':0x5c6ed9,'reason':'call frontier 0x683780'}]
assert result['stack_at_call']['0xcc']=='0'
result.update(schema='wlab-callee-scenario-1',module_sha256=hashlib.sha256(b).hexdigest(),function={'start':0x5c6440,'end':0x5c6f0c,'sha256':hashlib.sha256(p.get_data(0x5c6440,0xacc)).hexdigest()},synthetic_entry_rsp=RSP,assumptions=['All recorded module memory reads equal the recorded disk bytes at the time of each read','Instruction bytes unchanged, valid stack and ordinary memory; no asynchronous mutation, exceptions or nonlocal transfers','Unsigned low32(entry RSP - 0x118) > 0x2400 at stack guard 0x5C677F','This is a conditional static path model, not runtime observation or all-global-state coverage','Incoming R8=0x46 as prepared by wrapper; RCX, RDX, R9 and stack argument 7 remain symbolic','RIP references are expressed as RVAs; synthetic stack addresses are analysis coordinates, not process addresses'],call={'site':0x5c6ed9,'target':0x683780,'rcx':0x17,'rdx':'incoming R9 (symbolic pointer passed by wrapper)','r8':'entry RSP - 0x4C; pointer to local DWORD','r9':0x10,'stack_arg5':'incoming RCX','stack_arg6':'incoming RDX','stack_arg7':0x2f,'stack_arg8':'incoming stack argument 7','local_u32_disk_scenario':0},conclusions={'runtime_observed':False,'runtime_globals_invariant':False,'bios_read_proven':False,'hardware_send_3724_proven':False,'exe_slot_writer_found':False,'code_preparation_proven':False,'next_callee_semantics':'unresolved'})
args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'scenario_instructions':len(trace),'unique_instructions':len({n['rva'] for n in trace}),'branches':len(branches),'global_reads':len(globs),'next_callee':'0x683780','local_u32':0}))
