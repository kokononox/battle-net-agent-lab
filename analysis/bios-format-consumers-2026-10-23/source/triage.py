"""Bounded, conservative syntactic CFG triage; never claims runtime reachability."""
from pathlib import Path
import os,json,struct,collections,hashlib
from pe_manual import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_RET,CS_GRP_CALL,CS_GRP_INT
from capstone.x86 import X86_OP_IMM
D=Path(__file__).resolve().parents[1];r=json.loads((D/'reports/discovery.json').read_text());p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');assert hashlib.sha256(p.b).hexdigest()==r['sha256']
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
candidates=[x for x in r['rip_candidates'] if 'hardware_log_two_pages' in x['target_spans']];traces=[]
for c in candidates:
 lo,hi=c['pdata_owner'];todo=collections.deque([lo]);seen={};stops=[];edges=[]
 while todo and len(seen)<5000:
  a=todo.popleft()
  if a in seen:continue
  if not lo<=a<hi:stops.append({'rva':a,'reason':'outside_pdata_body'});continue
  raw=p.read(a,min(15,hi-a));i=next(md.disasm(raw,a,count=1),None)
  if i is None:stops.append({'rva':a,'reason':'decode_failure'});seen[a]=None;continue
  seen[a]={'rva':a,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
  targets=[]
  if i.group(CS_GRP_RET) or i.mnemonic in ['ud2','hlt'] or i.group(CS_GRP_INT):stops.append({'rva':a,'reason':'return_trap_or_stop'});continue
  if i.group(CS_GRP_JUMP):
   if i.operands and i.operands[0].type==X86_OP_IMM:
    targets.append(i.operands[0].imm)
   else:stops.append({'rva':a,'reason':'indirect_jump_unresolved'})
   if i.mnemonic!='jmp':targets.append(a+i.size)
  else:
   # Calls assumed to possibly return; not analyzed and may fault/throw/change code.
   targets.append(a+i.size)
  for t in targets:edges.append([a,t]);todo.append(t)
 ins=[x for x in seen.values() if x];ordered=sorted(ins,key=lambda x:x['rva']);overlaps=[]
 for a,b in zip(ordered,ordered[1:]):
  if a['rva']+len(bytes.fromhex(a['bytes']))>b['rva']:overlaps.append([a['rva'],b['rva']])
 traces.append({'candidate_rva':c['rva'],'pdata':[lo,hi],'entry_prefix_sha256':hashlib.sha256(p.read(lo,min(32,hi-lo))).hexdigest(),'candidate_visited':c['rva'] in seen and seen[c['rva']] is not None,'instructions':ordered,'edges':edges,'stops':stops,'overlaps':overlaps,'state_limit_hit':bool(todo),'claim':'This is a syntactic model from pdata entry, not proof of runtime paths or absence of middle-entry/exception paths.'})
# Identify ASCII objects reached by the neighbouring-page relocation pointers, not BIOS.
contexts=[]
for x in r['relocation_pointer_candidates']:
 if 'hardware_log_two_pages' not in x['target_spans']:continue
 a=x['target_rva'];sec=next(s for s in r['sections'] if s['rva']<=a<s['rva']+s['raw_size']);off=sec['file_offset']+a-sec['rva'];lo=p.b.rfind(b'\0',max(sec['file_offset'],off-512),off)+1;hi=p.b.find(b'\0',off,min(len(p.b),off+512));raw=p.b[lo:hi]
 contexts.append({'slot_rva':x['slot_rva'],'target_rva':a,'containing_string_rva':sec['rva']+lo-sec['file_offset'],'target_offset_in_string':off-lo,'ascii_context':raw.decode('ascii',errors='replace'),'inside_bios_format':r['bios_rva']<=a<r['bios_rva']+len(r['bios_format'])+1})
# Local surrounding bytes for ambiguous DWORD arithmetic matches; not inferred tables.
relative=[]
for x in r['bios_self_relative_dword_candidates']:
 a=x['slot_rva'];relative.append({**x,'alignment_mod4':a%4,'context_start_rva':a-8,'context_hex':p.read(a-8,20).hex(),'semantic_pointer_proven':False})
result={'traces':traces,'relocation_target_contexts':contexts,'relative_numeric_match_triage':relative,'limits':'No symbolic flag/value propagation; both conditional successors explored, calls may return, native exceptions/mid-body entries/self-modification not modeled. A visited overlapping candidate still does not prove a genuine use.'}
(D/'reports/triage.json').write_text(json.dumps(result,indent=2)+'\n')
for t in traces:print(hex(t['candidate_rva']),'entry',hex(t['pdata'][0]),'instructions',len(t['instructions']),'visited',t['candidate_visited'],'overlaps',len(t['overlaps']),'stops',t['stops'][:5])
for x in contexts:print('PTR',hex(x['slot_rva']),'=>',repr(x['ascii_context']))
