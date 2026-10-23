"""Byte-bound provenance and length model. No PE is executed or modified."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_IMM
from z3 import *
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
SEGMENTS=[('record_chain',0x14c2225,38),('record_preservation',0x14c224b,24),('length_arithmetic',0x14c22e3,0x14c2335-0x14c22e3),('shift',0x14c2374,6),('argument_preparation',0x14c2414,65),('wrapper_entry',0x15b40a0,12),('wrapper_transfer',0x15b40eb,40),('consumer_inputs',0x68379b,24),('consumer_end',0x6837eb,5),('length_jump',0x14c2335,2)]+[(f'guard_{a:x}',a,n) for a,n in [(0x14c237a,2),(0x14c237c,2),(0x14c23b2,2),(0x14c23bc,2),(0x14c23c8,2),(0x14c23d4,2),(0x14c23d6,3),(0x14c23d9,2),(0x14c2403,1),(0x14c2404,2),(0x15b40ac,2),(0x15b40ae,2),(0x15b40b0,2),(0x15b40dd,2),(0x15b40e9,2)]]
ASSUMPTIONS=['Conditional on reaching 0x14C2225 and its nonempty-list branch; code unchanged and ordinary valid reads; no concurrent loader-list mutation','Structure names assume ordinary Windows x64 GS/TEB semantics and the cited reference layout, not an observed OS build or runtime memory snapshot','The half-length formula requires word global G=0xF92D at the read; no runtime invariance is assumed','Transfer through 0x5C6440 inherits the rechecked previous static disk-global scenario and stack guard; it is not an observed execution']
def analyze(inp,out):
 b=inp.read_bytes();assert hashlib.sha256(b).hexdigest()==PIN;p=pefile.PE(data=b);cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
 trace=[];L=BitVec('record_word_58',16);G=BitVec('word_global',16)
 roots={k:BitVecVal(0,64) for k in ['rax','rcx','rdx','r8','r9','r10']};aliases={}
 for root,names in [('rax',['rax','eax','al']),('rcx',['rcx','ecx','cl','ch']),('rdx',['rdx','edx']),('r8',['r8','r8d']),('r9',['r9','r9d']),('r10',['r10','r10d'])]:
  for name in names:aliases[name]=(root,64 if name==root else 32 if name.endswith('d') or name.startswith('e') else 8,8 if name=='ch' else 0)
 def get(name):
  root,w,shift=aliases[name];return roots[root] if w==64 else Extract(shift+w-1,shift,roots[root])
 def put(name,v):
  root,w,shift=aliases[name]
  if v.size()!=w:v=Extract(w-1,0,v) if v.size()>w else ZeroExt(w-v.size(),v)
  if w==64:roots[root]=v
  elif w==32:roots[root]=ZeroExt(32,v)
  elif shift:roots[root]=Concat(Extract(63,16,roots[root]),v,Extract(7,0,roots[root]))
  else:roots[root]=Concat(Extract(63,w,roots[root]),v)
  roots[root]=simplify(roots[root])
 def val(i,o):
  if o.type==X86_OP_REG:return get(i.reg_name(o.reg))
  assert o.type==X86_OP_IMM;return BitVecVal(o.imm%(1<<(o.size*8)),o.size*8)
 global_rva=None
 for start,n in [(0x14c22e3,0x14c2335-0x14c22e3),(0x14c2374,6)]:
  decoded=list(cs.disasm(p.get_data(start,n),start));assert sum(i.size for i in decoded)==n
  for i in decoded:
   trace.append({'rva':i.address,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});o=i.operands;m=i.mnemonic;name=i.reg_name(o[0].reg)
   if m=='movzx':
    if i.address==0x14c22e3:assert i.reg_name(o[1].mem.base)=='rax' and o[1].mem.disp==0x58;v=L
    else:
     assert i.address==0x14c22e7 and i.reg_name(o[1].mem.base)=='rip';global_rva=i.address+i.size+o[1].mem.disp;v=G
    put(name,v)
   elif m=='lea':
    mm=o[1].mem;v=BitVecVal(mm.disp%(1<<64),64)
    if mm.base:v+=get(i.reg_name(mm.base))
    if mm.index:v+=get(i.reg_name(mm.index))*mm.scale
    put(name,v)
   elif m=='mov':put(name,val(i,o[1]))
   elif m=='not':put(name,~get(name))
   elif m=='inc':put(name,get(name)+1)
   elif m in ('xor','and','or','add','sub'):
    a,c=get(name),val(i,o[1]);assert a.size()==c.size();v={'xor':lambda:a^c,'and':lambda:a&c,'or':lambda:a|c,'add':lambda:a+c,'sub':lambda:a-c}[m]();put(name,v)
   elif m=='shr':
    assert name=='rax';shift=ZeroExt(56,get('cl'))&63;put(name,LShR(get(name),shift))
   else:raise AssertionError('Unsupported '+m)
 N=simplify(get('rax'));disk=int.from_bytes(p.get_data(global_rva,2),'little');assert global_rva==0x20f9b98 and disk==0xf92d
 def solve(q):
  s=Solver();s.set(timeout=10000);s.add(q);r=s.check();assert r in (sat,unsat);return s,r
 proofs={}
 for label,q in [('disk_shift_is_one',And(G==disk,shift!=1)),('disk_N_is_half_word',And(G==disk,N!=LShR(ZeroExt(48,L),1)))]:
  _,status=solve(q);assert status==unsat;proofs[label]=str(status)
 nd=simplify(substitute(N,(G,BitVecVal(disk,16))));U=BitVec('record_buffer_60',64)
 for label,q in [('even_byte_extent',And((L&1)==0,2*nd!=ZeroExt(48,L))),('all_byte_extent',2*nd!=ZeroExt(48,L&0xfffe)),('source_end',U+2*nd!=U+ZeroExt(48,L&0xfffe))]:
  _,status=solve(q);assert status==unsat;proofs[label]=str(status)
 s,status=solve(shift!=1);assert status==sat;w=s.model().eval(G,model_completion=True).as_long();count=simplify(substitute(shift,(G,BitVecVal(w,16)))).as_long();assert count!=1
 counterexample={'kind':'solver witness, not runtime observation','global_word':w,'effective_shift':count,'record_word':2,'N':2>>count,'half_word':1}
 from baseline_5c6440 import replay,verify
 from pe_manual import PE
 baseline_path=Path(__file__).resolve().parent.parent/'baseline/5c6440-scenario-proof.json';prior=json.loads(baseline_path.read_text());manual=PE(inp);expected=replay(manual);verify(prior,manual,expected)
 sections=[{'name':label,'rva':a,'bytes':p.get_data(a,n).hex()} for label,a,n in SEGMENTS]
 result={'schema':'wlab-record-provenance-1','module_sha256':PIN,'assumptions':ASSUMPTIONS,'byte_sections':sections,'arithmetic_trace':trace,'word_global':{'rva':global_rva,'disk_u16':disk,'runtime_invariant':False},'symbolic':{'effective_shift_smt2':simplify(shift).sexpr(),'N_smt2':N.sexpr()},'proofs':proofs,'noninvariant_counterexample':counterexample,'layout_mapping':{'TEB.ProcessEnvironmentBlock':0x60,'PEB.Ldr':0x18,'PEB_LDR_DATA.InLoadOrderModuleList':0x10,'LDR_DATA_TABLE_ENTRY.InLoadOrderLinks':0,'UNICODE_STRING.Buffer':8,'LDR_DATA_TABLE_ENTRY.BaseDllName':0x58,'record_length_offset':0x58,'record_buffer_offset':0x60,'record_adjustment':0,'reference_layout_only':True,'runtime_os_build_confirmed':False},'transfer':{'U':'qword(record + 0x60)','L':'word(record + 0x58)','N_disk_scenario':'floor(L/2)','argument_path':['0x14C2450: RCX=N, R8=U','0x15B410E: RDX=U, stack argument 7=N','0x5C6ED9: stack argument 6=U, stack argument 8=N','0x68379B..0x6837EF: source range U..U+2*N'],'baseline_5c6440_rechecked':True,'baseline_report_sha256':hashlib.sha256(baseline_path.read_bytes()).hexdigest()},'conclusions':{'static_reference_layout_interpretation':'loaded-module BaseDllName descriptor','actual_module_name_observed':False,'runtime_execution_observed':False,'BIOS_read_proven':False,'CPU_BIOS_send_3724_proven':False,'absence_of_hardware_send_proven':False,'runtime_contents_decoded':False,'core_6995d0_analyzed':False,'pause_deeper_generic_callee_expansion':True,'next_work':'Return to dedicated hardware-collection/message-population evidence; do not continue this generic name-buffer branch solely for 3724'}}
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'global_rva':hex(global_rva),'disk_word':hex(disk),'proofs':proofs,'noninvariant_witness':counterexample,'baseline_transfer_rechecked':True}))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--input',required=True,type=Path);a.add_argument('--out',required=True,type=Path);args=a.parse_args();assert args.out.resolve()!=args.input.resolve();analyze(args.input,args.out)
