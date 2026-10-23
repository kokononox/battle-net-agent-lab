"""Bounded rooted offline inventory. No execution, runtime binding, or whole-program proof."""
from pathlib import Path
import json,hashlib,struct,bisect,collections
from capstone import CS_AC_READ,CS_AC_WRITE
from capstone.x86 import *
from pe_manual import PE
from reachability import walk
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'))
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';assert hashlib.sha256(p.b).hexdigest()==PIN
pr,ps=p.dirs[3];bounds=[struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12)];starts=[x[0] for x in bounds]
def owner(a):
 i=bisect.bisect_right(starts,a)-1
 return bounds[i] if i>=0 and a<bounds[i][1] else None
# Metadata roots, plus specifically documented control-flow/array anchors.
roots=[('pe_entry',p.ep),('tls_first',p.tls()[0]['callback_rva']),('tls_second',p.tls()[1]['callback_rva'])]
anchors=[('dllmain_body_via_200658d',0x1beb830),('process_init_via_20064f4',0x2006320),('thread_init_array_on_disk_not_runtime',p.u(0x209f340,'<Q')-p.base)]
q=collections.deque((a,0,role) for role,a in roots+anchors);seen=set();rows=[];deferred=[];maxfunc=36;maxdepth=2
while q and len(rows)<maxfunc:
 a,depth,via=q.popleft()
 if a in seen:continue
 seen.add(a);own=owner(a)
 if not own or own[0]!=a:deferred.append({'target':a,'reason':'not_exact_pdata_entry','via':via});continue
 row,nodes=walk(p.read,*own,cap=10000);row.update({'depth':depth,'via':via});ins=[];calls=[];out=[];rip=[];peh=[];computed=[]
 for addr,i in sorted(nodes.items()):
  evidence={'rva':addr,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str};ins.append(evidence)
  if i.mnemonic in ['call','jmp']:
   op=i.operands[0]
   if op.type==X86_OP_IMM:
    t=op.imm
    if i.mnemonic=='call' or not own[0]<=t<own[1]:
     e={**evidence,'target':t};calls.append(e)
     if depth<maxdepth:q.append((t,depth+1,hex(addr)))
     else:deferred.append({**e,'reason':'depth_bound'})
   else:
    e={**evidence,'runtime_target_unresolved':True}
    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
     slot=addr+i.size+op.mem.disp;e['slot_rva']=slot
     try:e['disk_qword']=p.u(slot,'<Q')
     except AssertionError:e['disk_qword']=None
    out.append(e)
  for op in i.operands:
   if op.type==X86_OP_MEM:
    m=op.mem
    if m.base==X86_REG_RIP:
     t=addr+i.size+m.disp;rip.append({**evidence,'target_rva':t,'access':op.access})
    elif m.base not in [X86_REG_RSP,X86_REG_RBP] and i.mnemonic!='lea':
     computed.append({**evidence,'disp':m.disp,'access':op.access,'read':bool(op.access&CS_AC_READ),'write':bool(op.access&CS_AC_WRITE)})
    if m.disp==0x3c:peh.append({**evidence,'reason':'e_lfanew_offset_heuristic_only'})
   elif op.type==X86_OP_IMM and (op.imm&0xffffffff) in [0x5a4d,0x4550,0x2270000,0x2210000,0x5d0000]:peh.append({**evidence,'reason':'PE_or_section_constant_heuristic_only'})
 row.update({'instructions':ins,'direct_transfers':calls,'indirect_transfers':out,'rip_operands':rip,'computed_memory_operands':computed,'pe_heuristics':peh});rows.append(row)
print('FUNCTIONS',len(rows),'PENDING',len(q),'DEFERRED',len(deferred))
for x in rows:print(hex(x['begin']),x['via'],'closed',x['closed_under_stated_model'],'nodes',len(x['instructions']),'indirect',len(x['indirect_transfers']),'PE hints',len(x['pe_heuristics']))
result={'sha256':PIN,'roots':roots,'additional_anchors':anchors,'anchor_caveat':'Local direct-call sites and one TLS thread-init on-disk table value; NOT a claim every anchor executes. All reasons explored unless separately described. Calls may return and clobber flags; register/memory effects and exceptions not modeled.','limits':{'functions':maxfunc,'depth':maxdepth,'states_per_function':10000},'functions':rows,'deferred':deferred,'pending':list(q),'claims':{'eid_consumer_identified':False,'decryptor_identified':False,'runtime_chain_proven':False}}
(D/'reports/rooted.json').write_text(json.dumps(result,indent=2)+'\n')
