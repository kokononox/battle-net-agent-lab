"""Bounded follow-up of registration anchor. No runtime call-chain claim."""
from pathlib import Path
import json,struct,hashlib
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM
from pe_manual import PE
from reachability import walk
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/wow_loader.dll'));PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';assert hashlib.sha256(p.b).hexdigest()==PIN
d=json.loads((D/'reports/discovery.json').read_text());pr,ps=p.dirs[3];bounds=dict(struct.unpack('<III',p.read(pr+i,12))[:2] for i in range(0,ps,12));model,nodes=walk(p.read,0x957f00,bounds[0x957f00]);candidate_status=[]
for c in d['syntactic_candidates']:
 assert c['function']==[model['begin'],model['end']], 'New owner requires its own model; do not exclude using helper boundaries.'
 i=nodes.get(c['rva']);seen=bool(i and i.bytes.hex()==c['bytes']);candidate_status.append({**c,'seen_on_helper_model_boundary':seen,'excluded_only_under_closed_helper_model':not seen and model['closed_under_stated_model']})
# Exact literals only. Full-file byte occurrence != a semantic pointer/reference.
raw=[]
for label,val,fmt in [('anchor_rva32',0x20d2d18,'<I'),('anchor_preferred_va64',p.base+0x20d2d18,'<Q'),('initial_node_rva32',d['initial_node_disk_fields']['rva'],'<I'),('initial_node_preferred_va64',p.base+d['initial_node_disk_fields']['rva'],'<Q')]:
 n=struct.pack(fmt,val);hits=[];at=0
 while (at:=p.b.find(n,at))>=0:hits.append(at);at+=1
 raw.append({'label':label,'value':val,'needle_hex':n.hex(),'file_offsets':hits})
# Follow only the on-disk initial node already read by the producer.
node=d['initial_node_disk_fields'];target=node['first_qword']-p.base;assert target in bounds
callback,cn=walk(p.read,target,bounds[target],cap=10000)
callback['instructions']=[{'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str} for a,i in sorted(cn.items())]
callback['direct_call_candidates']=[{'rva':a,'bytes':i.bytes.hex(),'target_rva':i.operands[0].imm} for a,i in sorted(cn.items()) if i.mnemonic=='call' and i.operands[0].type==X86_OP_IMM]
callback['candidate_caveat']='Instructions/call sites explored in an incomplete model are NOT confirmed runtime paths or true call-chain links.'
out={'sha256':PIN,'candidate_status':candidate_status,'helper_closed_under_model':model['closed_under_stated_model'],'raw_literal_occurrences':raw,'initial_node_callback_model':callback,'claims':{'independent_anchor_consumer_identified':False,'registration_list_invocation_proven':False,'eid_consumer_identified':False,'decryptor_identified':False,'runtime_execution_observed':False}}
(D/'reports/trace.json').write_text(json.dumps(out,indent=2)+'\n')
print('Anchor candidates',[(hex(x['rva']),x['seen_on_helper_model_boundary']) for x in candidate_status]);print('Exact raw literals',[(x['label'],len(x['file_offsets'])) for x in raw]);print('Initial callback',hex(target),'nodes',len(cn),'closed',callback['closed_under_stated_model'],'overlap pairs',len(callback['overlapping_instruction_pairs']),'calls only candidates',len(callback['direct_call_candidates']))
