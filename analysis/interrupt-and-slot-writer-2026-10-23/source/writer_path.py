from pathlib import Path
from pe_manual import PE
from capstone import *
from z3 import *
import json,hashlib
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));digest=hashlib.sha256(p.b).hexdigest();assert digest=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';m=Cs(CS_ARCH_X86,CS_MODE_64)
path=[0x902b54,0x902b58,0x902b5d,0x902bd0,0x902bd5,0x902bdb,0x902be0,0x902e58,0x902e5d,0x903288,0x90328d,0x904504,0x904509,0x90593b]
x=BitVec('initial_global_u32',32);eax=x^0x9d1bc029;state=(((x^0x9cd9d325)+eax+0xf55ae0d7)^(eax+0x343f518a));conds=[];nodes=[];last=None
for idx,a in enumerate(path):
 i=next(m.disasm(p.read(a,15),a,count=1));row={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str};nodes.append(row)
 if i.mnemonic=='cmp':last=int(i.op_str.split(', ')[1],0)
 elif i.mnemonic in ['je','jne','jg','jge','jl','jle']:
  q={'je':state==last,'jne':state!=last,'jg':state>last,'jge':state>=last,'jl':state<last,'jle':state<=last}[i.mnemonic];taken=path[idx+1]==int(i.op_str,16);conds.append(q if taken else Not(q));row['taken']=taken
s=Solver();s.set(timeout=15000);s.add(*conds);result=s.check();assert result==sat;w=s.model().eval(x,model_completion=True).as_long()
g=0x902a9d+p.u(0x902a99,'<i');prologue=p.read(0x902a40,0x902ad9-0x902a40)
assert p.read(0x90593b,15).hex()=='488b8424380300004889057e648901'
assert 0x90594a+p.u(0x905946,'<i')==0x219bdc8
r={'sha256':digest,'function_range':[0x902a40,0x905aa6],'entry_prefix':{'rva':0x902a40,'bytes':prologue.hex(),'scope':'Straight-line prologue ending with direct JMP to dispatcher; no calls.'},'initial_global_rva':g,'initial_global_policy':'symbolic DWORD; not fixed to disk or claimed as observed runtime','state_smt':state.sexpr(),'path':nodes,'path_smt_result':str(result),'witness_global_u32':w,'witness_state_u32':simplify(substitute(state,(x,BitVecVal(w,32)))).as_long(),'store_block':{'rva':0x90593b,'bytes':p.read(0x90593b,15).hex(),'load':'RAX <- [RSP+0x338]','store_rva':0x905943,'destination_slot_rva':0x219bdc8,'stored_value_provenance':'local stack slot only; prior initialization and runtime pointer unresolved'},'claims':{'static_store_instruction_verified':True,'model_path_to_store_satisfiable':True,'observed_runtime_store':False,'runtime_pointer_recovered':False,'target_page_preparation_proven':False}}
Path('/data/wlab-interrupt-slot-review/writer-path.json').write_text(json.dumps(r,indent=2));print('SAT witness',hex(w),'state',hex(r['witness_state_u32']),'global',hex(g))
