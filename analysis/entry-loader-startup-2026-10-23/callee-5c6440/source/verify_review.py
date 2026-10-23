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
def replay(p,seed_override=None):
 cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
 aliases={};r={};stack={};reads={};writes=[];trace=[];branches=[];flags={}
 for family,alts in [('rax','rax eax ax al ah'),('rbx','rbx ebx bx bl bh'),('rcx','rcx ecx cx cl ch'),('rdx','rdx edx dx dl dh'),('rsi','rsi esi si sil'),('rdi','rdi edi di dil'),('rsp','rsp esp sp spl'),('rbp','rbp ebp bp bpl')]+[(f'r{x}',f'r{x} r{x}d r{x}w r{x}b') for x in range(8,16)]:
  r[family]=0x600000000000+len(r)*0x100
  for k,name in enumerate(alts.split()):aliases[name]=(family,[64,32,16,8,8][k],8 if k==4 else 0)
 r.update(rsp=BASE,rcx=MARKERS['rcx'],rdx=MARKERS['rdx'],r8=0x46,r9=MARKERS['r9'])
 def reg(name):
  root,w,shift=aliases[name];return (r[root]>>shift)&((1<<w)-1)
 def setreg(name,v):
  root,w,shift=aliases[name];v&=(1<<w)-1
  r[root]=v if w in (32,64) else (r[root]&~(((1<<w)-1)<<shift))|(v<<shift)
 def store(a,v,n):
  assert BASE-0x1000<=a and a+n<=BASE+0x100,'nonstack write'
  writes.append((a,n))
  for k in range(n):stack[a+k]=(v>>(8*k))&255
 def load(a,n):
  if BASE-0x1000<=a<BASE+0x100:return sum(stack[a+k]<<(8*k) for k in range(n))
  raw=p.read(a,n);reads[(a,n)]=raw.hex()
  if seed_override is not None and a==0x20e0e58 and n==4:return seed_override
  return int.from_bytes(raw,'little')
 store(BASE+0x28,0x21,8);store(BASE+0x30,0x1c,8);store(BASE+0x38,MARKERS['arg7'],8)
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
 ip=0x5c6440
 for _ in range(4000):
  assert 0x5c6440<=ip<0x5c6f0c
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
  elif m=='call':
   assert ip==0x5c6ed9 and o[0].imm==0x683780
   assert r['rsp']==BASE-0x118
   return {'trace':trace,'branches':branches,'global_reads':[{'rva':a,'size':n,'bytes':h} for (a,n),h in sorted(reads.items())],'args':[r['rcx'],r['rdx'],r['r8']-BASE,r['r9'],load(r['rsp']+0x20,8),load(r['rsp']+0x28,8),load(r['rsp']+0x30,8),load(r['rsp']+0x38,8)],'payload':load(r['rsp']+0xcc,4),'writes_only_stack':True}
  else:raise AssertionError('unsupported '+m)
  ip=n
 raise AssertionError('budget')
def verify(report,p,expected):
 assert report['schema']=='wlab-callee-scenario-1' and report['module_sha256']==PIN==hashlib.sha256(p.b).hexdigest()
 assert report['synthetic_entry_rsp']==BASE
 assert report['function']=={'start':0x5c6440,'end':0x5c6f0c,'sha256':hashlib.sha256(p.read(0x5c6440,0xacc)).hexdigest()}
 d,size=p.dirs[3];assert any(p.read(a,8)==struct.pack('<II',0x5c6440,0x5c6f0c) for a in range(d,d+size,12))
 assert report['trace']==expected['trace'] and report['branches']==expected['branches'] and report['global_reads']==expected['global_reads']
 assert report['final_registers']['rdx']=='entry_r9' and report['final_registers']['rcx']=='23' and report['final_registers']['r9']=='16'
 assert report['final_registers']['r8']==str(BASE-0x4c)
 assert p.read(0x15b40a0,12).hex()=='4883ec384c89c04c8b4c2468'
 assert p.read(0x15b40eb,len(bytes.fromhex('48894c243048c74424281c00000048c74424202100000041b8460000004889d14889c2e82d2301ff90'))).hex()=='48894c243048c74424281c00000048c74424202100000041b8460000004889d14889c2e82d2301ff90'
 assert report['events']==[{'kind':'frontier','site':0x5c6ed9,'reason':'call frontier 0x683780'}]
 call={'site':0x5c6ed9,'target':0x683780,'rcx':0x17,'rdx':'incoming R9 (symbolic pointer passed by wrapper)','r8':'entry RSP - 0x4C; pointer to local DWORD','r9':0x10,'stack_arg5':'incoming RCX','stack_arg6':'incoming RDX','stack_arg7':0x2f,'stack_arg8':'incoming stack argument 7','local_u32_disk_scenario':0}
 assert report['call']==call
 assert expected['args']==[0x17,MARKERS['r9'],-0x4c,0x10,MARKERS['rcx'],MARKERS['rdx'],0x2f,MARKERS['arg7']] and expected['payload']==0
 assert report['stack_at_call']=={'0x20':'entry_rcx','0x28':'entry_rdx','0x30':'47','0x38':'arg7','0x4c':'3447115121','0x48':'2462616063','0x50':'1003908702','0x54':'2663672126','0xcc':'0'}
 assert len(report['assumptions'])==6
 assert report['assumptions'][0]=='All recorded module memory reads equal the recorded disk bytes at the time of each read'
 assert report['assumptions'][2]=='Unsigned low32(entry RSP - 0x118) > 0x2400 at stack guard 0x5C677F'
 assert report['assumptions'][3]=='This is a conditional static path model, not runtime observation or all-global-state coverage'
 assert report['conclusions']=={'runtime_observed':False,'runtime_globals_invariant':False,'bios_read_proven':False,'hardware_send_3724_proven':False,'exe_slot_writer_found':False,'code_preparation_proven':False,'next_callee_semantics':'unresolved'}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--report',required=True,type=Path);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args();assert a.out.resolve()!=a.input.resolve(), "Output must not replace input";p=PE(a.input);r=json.loads(a.report.read_text());expected=replay(p);verify(r,p,expected)
 tests=[]
 muts=[('changed_call_target',lambda q:q['call'].__setitem__('target',0x683781)),('wrong_pointer_offset',lambda q:q['call'].__setitem__('r8','entry RSP - 0x48')),('changed_payload',lambda q:q['call'].__setitem__('local_u32_disk_scenario',1)),('removed_global_condition',lambda q:q['assumptions'].__setitem__(0,'Unconditional')),('removed_stack_guard',lambda q:q['assumptions'].__setitem__(2,'No stack guard')),('changed_instruction',lambda q:q['trace'][0].__setitem__('bytes','90')),('flipped_branch',lambda q:q['branches'][0].__setitem__('taken',not q['branches'][0]['taken'])),('deleted_instruction',lambda q:q['trace'].pop(50)),('changed_global',lambda q:q['global_reads'][0].__setitem__('bytes','00'*8)),('claimed_send',lambda q:q['conclusions'].__setitem__('hardware_send_3724_proven',True)),('claimed_runtime_invariant',lambda q:q['conclusions'].__setitem__('runtime_globals_invariant',True))]
 for label,fn in muts:
  q=copy.deepcopy(r);fn(q)
  try:verify(q,p,expected)
  except AssertionError:tests.append({'mutation':label,'rejected':True})
  else:raise AssertionError('accepted mutation '+label)
 alternate=replay(p,0)
 result={'manual_PE_mapping':'passed','separate_integer_semantics_replay':'passed','shared_decoder':'Capstone; not an independent disassembler','instructions_in_conditional_trace':len(expected['trace']),'unique_instruction_starts':len({n['rva'] for n in expected['trace']}),'conditional_branches':len(expected['branches']),'recorded_global_reads':len(expected['global_reads']),'writes_only_to_model_stack_before_call':expected['writes_only_stack'],'call_and_argument_transfer':'passed','payload_disk_scenario':expected['payload'],'payload_seed_counterexample':{'seed_rva':'0x20E0E58','disk_seed':hex(p.u(0x20e0e58,'<I')),'alternate_seed':0,'alternate_payload':alternate['payload'],'same_instruction_rvas':[n['rva'] for n in alternate['trace']]==[n['rva'] for n in expected['trace']],'interpretation':'Synthetic data sensitivity check, not input patch or runtime observation'},'mutation_tests':tests,'input_PE_executed':False}
 assert alternate['payload']!=0
 a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
