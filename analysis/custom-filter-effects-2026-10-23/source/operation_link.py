from pathlib import Path
from pe_manual import PE
import json,struct,hashlib
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));h=hashlib.sha256(p.b).hexdigest();assert h=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
s=json.load(open('/data/wlab-handler-triage/scope-tables.json'));t=next(t for t in s['tables'] if t['function_begin']==0x1ff6330);scope=next(x for x in t['scopes'] if x['filter_or_finally']==0xc59140)
assert scope=={'begin':0x1ff67c5,'end':0x1ff67db,'filter_or_finally':0xc59140,'jump_target':0x1ff67da,'kind':'except'}
assert p.read(0x1ff67c5,17).hex()=='b930000000ba1b00000041b84f000000e8'
a=0x1ff67d5;assert p.read(a,1)==b'\xe8';callee=a+5+p.u(a+1,'<i');assert callee==0xdeea10
assert p.read(callee,21).hex()=='4883ec28b962000000ba2300000041b83e000000e8'
a2=0xdeea24;next_=a2+5+p.u(a2+1,'<i');assert next_==0x74a8e0
r={'sha256':h,'scope':scope,'parent_function':t['function_begin'],'first_call':{'site':a,'callee':callee,'call_bytes':p.read(a,5).hex(),'prepared_registers':{'ecx':0x30,'edx':0x1b,'r8d':0x4f}},'callee_prefix':{'rva':callee,'bytes':p.read(callee,25).hex(),'next_call_site':a2,'next_callee':next_,'prepared_registers':{'ecx':0x62,'edx':0x23,'r8d':0x3e}},'scope_end_is_not_an_instruction_boundary':True,'boundary_note':'The next MOV starts at 0x1ff67da, which is also the metadata jump target. Scope end is 0x1ff67db. The interval is reported exactly, not rounded to decoder instruction boundaries.','callee_semantics':'unresolved; prefix and relative-call targets only','runtime_observed':False,'code_preparation_proven':False}
Path('/data/wlab-filter-effects/operation-link.json').write_text(json.dumps(r,indent=2));print('scope link and two relative calls verified')
