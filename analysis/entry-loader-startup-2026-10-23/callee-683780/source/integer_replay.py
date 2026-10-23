"""Separate Python-integer replay with manual PE mapping. Capstone decoder is shared.
Does not execute the PE, call its APIs, or follow calls. Fails closed at unsupported ops.
"""
import argparse,copy,hashlib,json,struct
from pathlib import Path
from pe_manual import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_IMM
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
BASE=0x1000000008
MARKERS={'rcx':0x710000001111,'rdx':0x720000002222,'arg7':0x730000003333,'r9':0x740000004444}
def replay(p,phase,D,U,N,A,status):
 cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
 aliases={};r={};stack={};reads={};writes=[];trace=[];branches=[];flags={};returns=[];calls=[];external=[]
 for family,alts in [('rax','rax eax ax al ah'),('rbx','rbx ebx bx bl bh'),('rcx','rcx ecx cx cl ch'),('rdx','rdx edx dx dl dh'),('rsi','rsi esi si sil'),('rdi','rdi edi di dil'),('rsp','rsp esp sp spl'),('rbp','rbp ebp bp bpl')]+[(f'r{x}',f'r{x} r{x}d r{x}w r{x}b') for x in range(8,16)]:
  r[family]=0x600000000000+len(r)*0x100
  for k,name in enumerate(alts.split()):aliases[name]=(family,[64,32,16,8,8][k],8 if k==4 else 0)
 Q=0x700000005555;P=0x710000006666;MASK=(1<<64)-1
 r.update(rsp=BASE,rcx=0x17,rdx=Q,r8=P,r9=0x10)
 def reg(name):
  root,w,shift=aliases[name];return (r[root]>>shift)&((1<<w)-1)
 def setreg(name,v):
  root,w,shift=aliases[name];v&=(1<<w)-1
  r[root]=v if w in (32,64) else (r[root]&~(((1<<w)-1)<<shift))|(v<<shift)
 def store(a,v,n):
  if a==Q:
   external.append({'pointer':'Q','size':n,'value':v&((1<<(n*8))-1)});return
  assert BASE-0x1000<=a and a+n<=BASE+0x100,'nonstack write'
  writes.append((a,n))
  for k in range(n):stack[a+k]=(v>>(8*k))&255
 def load(a,n):
  if BASE-0x1000<=a<BASE+0x100:return sum(stack[a+k]<<(8*k) for k in range(n))
  raw=p.read(a,n);reads[(a,n)]=raw.hex()
  return int.from_bytes(raw,'little')
 store(BASE+0x28,D,8);store(BASE+0x30,U,8);store(BASE+0x38,0x2f,8);store(BASE+0x40,N,8)
 frame=BASE-0x108
 if phase=='suffix':
  r.update(rsp=frame,rbx=D,rbp=(~D)&MASK,r13=U,rsi=(U+2*N)&MASK,r14=frame+0xb0,r15=(D+256)&MASK,r12=frame+0xa0,rdi=P,rax=status)
  store(frame+0xa0,A,8);store(frame+0x50,Q,8);store(frame+0xc0,p.u(0x20d01c0,'<Q')^frame,8)
  for k,name in enumerate(['rbx','rbp','rdi','rsi','r12','r13','r14','r15']):store(frame+0xc8+k*8,0x800000000000+k*0x100,8)

 def address(i,o):
  m=o.mem;a=m.disp
  if m.base:a+=(i.address+i.size if i.reg_name(m.base)=='rip' else reg(i.reg_name(m.base)))
  if m.index:a+=reg(i.reg_name(m.index))*m.scale
  return a&0xffffffffffffffff
 def value(i,o):
  if o.type==X86_OP_REG:return reg(i.reg_name(o.reg))
  if o.type==X86_OP_IMM:return o.imm&((1<<(o.size*8))-1)
  return load(address(i,o),o.size)
 def assign(i,o,v):
  if o.type==X86_OP_REG:setreg(i.reg_name(o.reg),v)
  else:store(address(i,o),v,o.size)
 def common(v,w):flags.update(ZF=v==0,SF=bool(v&(1<<(w-1))),PF=(v&255).bit_count()%2==0)
 ip=0x683780 if phase=='prefix' else 0x683ca8
 for _ in range(4000):
  assert 0x683780<=ip<0x683d12 or 0x1948090<=ip<0x1948195 or 0xe83570<=ip<0xe83622
  i=next(cs.disasm(p.read(ip,15),ip,count=1));o=i.operands;m=i.mnemonic;n=ip+i.size
  trace.append({'rva':ip,'bytes':i.bytes.hex(),'mnemonic':m,'operands':i.op_str})
  if m=='push':v=value(i,o[0]);r['rsp']-=8;store(r['rsp'],v,8)
  elif m=='pop':v=load(r['rsp'],8);assign(i,o[0],v);r['rsp']+=8
  elif m in ('mov','movzx'):assign(i,o[0],value(i,o[1]))
  elif m=='lea':assign(i,o[0],address(i,o[1]))
  elif m in ('add','sub','cmp','xor','and','or','test'):
   a,b=value(i,o[0]),value(i,o[1]);w=o[0].size*8;mask=(1<<w)-1;sign=1<<(w-1)
   if o[1].size<o[0].size and b&(1<<(o[1].size*8-1)):b|=mask^((1<<(o[1].size*8))-1)
   b&=mask
   if m=='add':v=(a+b)&mask;flags.update(CF=a+b>mask,OF=bool((~(a^b)&(a^v))&sign))
   elif m in ('sub','cmp'):v=(a-b)&mask;flags.update(CF=a<b,OF=bool(((a^b)&(a^v))&sign))
   else:v={'xor':lambda:a^b,'and':lambda:a&b,'test':lambda:a&b,'or':lambda:a|b}[m]();flags.update(CF=False,OF=False)
   common(v,w)
   if m not in ('cmp','test'):assign(i,o[0],v)
  elif m=='imul':
   a,b=value(i,o[1]),value(i,o[2]);w=o[0].size*8;mask=(1<<w)-1
   def signed(v):return v-(1<<w) if v&(1<<(w-1)) else v
   full=signed(a)*signed(b);v=full&mask;overflow=not (-(1<<(w-1))<=full<(1<<(w-1)));flags={'CF':overflow,'OF':overflow};assign(i,o[0],v)
  elif m=='not':assign(i,o[0],~value(i,o[0]))
  elif m in ('neg','inc','dec'):
   a=value(i,o[0]);w=o[0].size*8;mask=(1<<w)-1
   if m=='neg':v=(-a)&mask;flags.update(CF=a!=0,OF=a==1<<(w-1))
   else:v=(a+(1 if m=='inc' else -1))&mask;flags['OF']=a==((1<<(w-1))-1 if m=='inc' else 1<<(w-1))
   common(v,w);assign(i,o[0],v)
  elif m in ('sar','shr','shl'):assert value(i,o[1])&(63 if o[0].size==8 else 31)==0
  elif m=='xchg':a,b=value(i,o[0]),value(i,o[1]);assign(i,o[0],b);assign(i,o[1],a)
  elif m in ('clc','stc'):flags['CF']=m=='stc'
  elif m=='nop':pass
  elif m=='jmp':n=o[0].imm
  elif m.startswith('j'):
   z,s,ov,c,pf=[flags[q] for q in ('ZF','SF','OF','CF','PF')]
   take={'je':z,'jne':not z,'jg':not z and s==ov,'jge':s==ov,'jl':s!=ov,'jle':z or s!=ov,'ja':not c and not z,'jae':not c,'jb':c,'jbe':c or z,'jo':ov,'jno':not ov,'jp':pf,'jnp':not pf}[m]
   branches.append({'site':ip,'taken':take});n=o[0].imm if take else n
  elif m=='ret':
   if returns:
    n=returns.pop();assert load(r['rsp'],8)==n;r['rsp']+=8
   else:
    return {'trace':trace,'branches':branches,'reads':reads,'external':external,'calls':calls,'return':r['rax'],'frame':frame,'slots':{k:load(frame+k,8) for k in [0x60,0x68,0x70,0x78,0x80,0x88,0x90,0x98]}}
  elif m=='call':
   target=o[0].imm;calls.append({'site':ip,'target':target,'args':[r['rcx'],r['rdx'],r['r8'],r['r9'],load(r['rsp']+0x20,8),load(r['rsp']+0x28,8)]})
   if target in (0x1948090,0xe83570):returns.append(n);r['rsp']-=8;store(r['rsp'],n,8);n=target
   else:
    assert ip==0x683ca3 and target==0x6995d0
    return {'trace':trace,'branches':branches,'reads':reads,'external':external,'calls':calls,'spans':[load(frame+k,8) for k in [0xa0,0xa8,0xb0,0xb8]],'frame':frame}
  else:raise AssertionError('unsupported '+m)
  ip=n
 raise AssertionError('budget')
