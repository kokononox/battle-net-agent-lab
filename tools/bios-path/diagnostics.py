"""Expanded static reference scopes, with explicit non-exhaustive coverage.
No unpacking, emulation, process attachment or execution.
"""
import math,re,struct
from collections import Counter
from capstone.x86 import X86_OP_MEM,X86_OP_IMM,X86_REG_RIP,X86_REG_FS,X86_REG_GS
BUDGET={'raw_candidates':12000,'decode_attempts':200000,'sample_functions':128,'sample_instructions':64,'pointer_hops':1}
MODRM=re.compile(rb'(?=[\x05\x0d\x15\x1d\x25\x2d\x35\x3d][\s\S]{4})')

def expand(im,anchors,pointers,old_hits,cs,progress=lambda *_:None):
 targets={r:{'labels':list(labels),'hops':0,'pointer_chain':[]} for r,labels in anchors.items()}
 # Import slots are seeds for address references; loading one is NOT a registry call.
 for slot,name in im.imports.items():
  if name.split('!')[-1] in {'RegGetValueW','RegGetValueA','RegQueryValueExW','RegQueryValueExA','RegOpenKeyExW','RegOpenKeyExA'}:
   targets.setdefault(slot,{'labels':[name],'hops':0,'pointer_chain':[]})
 for p in pointers:
  targets.setdefault(p['site_rva'],{'labels':['pointer-slot -> '+x for x in p['target_labels']],
   'hops':1,'pointer_chain':[{'site_rva':p['site_rva'],'target_rva':p['target_rva']} ]})
 seen={(h['site_rva'],h['target_rva']) for h in old_hits};new=[];stops=[];attempts=0;modrms=0;scanned=0;abs_scanned=0
 def accept(ins,target,encoding):
  r=ins.address-im.base;k=(r,target)
  if k in seen:return
  seen.add(k);meta=targets[target];fun=im.function(r)
  hit={'site_rva':r,'target_rva':target,'target_labels':meta['labels'],'kind':'expanded_reference_candidate',
   'bytes':ins.bytes.hex(),'instruction':ins.mnemonic+' '+ins.op_str,'function_start_rva':fun[0] if fun else None,
   'cfg_status':'not_checked','discovery':'expanded','encoding':encoding,'anchor_hops':meta['hops'],
   'pointer_chain':meta['pointer_chain'],'pointer_dereference_proven':False}
  if encoding=='rip_relative_modrm':hit['operand_displacement_offset']=ins.disp_offset
  else:hit['operand_immediate_offset']=ins.imm_offset;hit['operand_immediate_size']=ins.imm_size
  new.append(hit)
 for va,end,off,sec in im.sections:
  if not sec.Characteristics&0x20000000:continue
  code=im.blob[off:off+end-va];completed=True
  progress(44,'Expanded RIP-relative scan: '+sec.Name.rstrip(b'\0').decode('ascii','replace'))
  for m in MODRM.finditer(code):
   pos=m.start();modrms+=1;disp=struct.unpack_from('<i',code,pos+1)[0]
   # RIP displacement can be followed by instruction immediates. Listed tails are
   # supported scopes, not a claim that every x86 encoding is covered.
   for tail in (0,1,2,4,8):
    target=va+pos+5+tail+disp
    if target not in targets:continue
    # The ModRM byte is inside an instruction. Try all file-backed starts up to
    # 14 bytes earlier and verify Capstone's displacement position and operand.
    for start in range(max(0,pos-14),pos):
     if attempts>=BUDGET['decode_attempts']:completed=False;break
     attempts+=1;ins=next(cs.disasm(code[start:start+15],im.base+va+start,count=1),None)
     if not ins or ins.disp_size!=4 or start+ins.disp_offset!=pos+1:continue
     if start+ins.size!=pos+5+tail:continue
     if any(op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP and (op.mem.segment not in (X86_REG_FS,X86_REG_GS) or ins.mnemonic=='lea') and va+start+ins.size+op.mem.disp==target for op in ins.operands):
      accept(ins,target,'rip_relative_modrm')
     if len(new)>=BUDGET['raw_candidates']:completed=False;break
    if not completed:break
   if not completed:break
  scanned+=len(code) if completed else min(len(code),pos+5)
  if not completed:
   stops.append('Expanded RIP scan stopped at a candidate/decode budget; remaining bytes NOT covered.');break
 # Absolute imm64 addresses, e.g. movabs. No inference for arbitrary embedded data.
 if attempts<BUDGET['decode_attempts'] and len(new)<BUDGET['raw_candidates']:
  for va,end,off,sec in im.sections:
   if not sec.Characteristics&0x20000000:continue
   code=im.blob[off:off+end-va];completed=True
   for target in sorted(targets):
    value=im.base+target
    if not 0<=value<2**64:continue
    needle=struct.pack('<Q',value);search=0
    while True:
     pos=code.find(needle,search)
     if pos<0:break
     search=pos+1
     for start in range(max(0,pos-14),pos):
      if attempts>=BUDGET['decode_attempts']:completed=False;break
      attempts+=1;ins=next(cs.disasm(code[start:start+15],im.base+va+start,count=1),None)
      if not ins or ins.imm_size!=8 or start+ins.imm_offset!=pos:continue
      if any(op.type==X86_OP_IMM and op.imm & ((1<<64)-1)==value for op in ins.operands):accept(ins,target,'absolute_imm64')
      if len(new)>=BUDGET['raw_candidates']:completed=False;break
     if not completed:break
    if not completed:break
   if completed:abs_scanned+=len(code)
   else:
    stops.append('Absolute-imm64 scan budget reached; this section is only partially searched.');break
 if attempts>=BUDGET['decode_attempts'] and not abs_scanned:
  stops.append('Absolute-imm64 pass not completed: decode-attempt budget exhausted.')
 diag={'baseline_code_candidates':len(old_hits),'expanded_new_code_candidates':len(new),
  'target_count_including_pointer_slots':len(targets),'new_one_hop_candidates':sum(h['anchor_hops']==1 for h in new),
  'rip_scope':{'bytes_scanned':scanned,'modrm_positions_checked':modrms,'supported_trailing_immediate_bytes':[0,1,2,4,8]},
  'absolute_imm64_scope':{'fully_searched_section_bytes':abs_scanned},'decode_attempts':attempts,
  'budget_limits_hit':stops,'limits':dict(BUDGET),'pointer_graph_semantics':'One edge represents stored pointer bytes, NOT an executed dereference.',
  'uncovered':['Address construction across multiple instructions','Encoded or encrypted pointers','Interior string references','More than one pointer-table hop','Absolute imm32/RVA-only encodings','Moffs64, FS/GS effective memory addresses and arbitrary non-RIP address forms','Unpacking and runtime-generated code','Whole-program dataflow and dynamic API resolution'],
  'root_cause':'not_determined','protection_proven':False,'hardware_dataflow_proven':False}
 return new,diag

def structural_samples(im,cs,cfg):
 sections=[]
 for a,b,off,sec in im.sections:
  n=b-a;parts=[]
  starts=sorted({min(max(0,int((n-4096)*fraction)),max(0,n-4096)) for fraction in (0,.25,.5,.75,1)})
  for start in starts:
   raw=im.blob[off+start:off+min(n,start+4096)]
   if raw:
    counts=Counter(raw);entropy=-sum((v/len(raw))*math.log2(v/len(raw)) for v in counts.values())
    parts.append({'rva':a+start,'size':len(raw),'entropy_bits_per_byte':round(entropy,4)})
  sections.append({'name':sec.Name.rstrip(b'\0').decode('ascii','replace'),'rva':a,'file_backed_size':n,
   'executable':bool(sec.Characteristics&0x20000000),'writable':bool(sec.Characteristics&0x80000000),
   'samples':parts,'caution':'Sample entropy is descriptive only. High entropy does NOT prove packing, encryption or protection.'})
 count=min(len(im.functions),BUDGET['sample_functions']);indexes=sorted({i*(len(im.functions)-1)//max(1,count-1) for i in range(count)})
 funcs=[]
 for i in indexes:
  fun=im.functions[i];instructions,edges,issues=cfg(im,fun,cs,cap=BUDGET['sample_instructions'])
  funcs.append({'start_rva':fun[0],'end_rva':fun[1],'decoded_instruction_count':len(instructions),
   'local_issues':issues,'caution':'Deterministic entry sample only; not the BIOS collector and not a runtime reachability test.'})
 return {'sections':sections,'function_samples':funcs,'sampling':'Evenly spaced pdata entries, at most 128; at most 64 instructions per entry.',
  'named_import_count':len(im.imports),'scope':'Triage only; no definitive protected/unprotected classification.'}

def finish(diag,hits):
 reached=[h for h in hits if h.get('discovery')=='expanded' and h['cfg_status']=='locally_decoded_from_pdata_entry']
 diag['expanded_locally_decoded_candidates']=len(reached)
 diag['expanded_direct_locally_decoded_candidates']=sum(h['anchor_hops']==0 for h in reached)
 diag['expanded_one_hop_locally_decoded_candidates']=sum(h['anchor_hops']==1 for h in reached)
 if reached:diag['outcome']='new_local_candidates_for_manual_review'
 elif diag['expanded_new_code_candidates']:diag['outcome']='raw_candidates_only_no_local_code_validation'
 else:diag['outcome']='no_reference_found_within_expanded_scope'
 diag['no_reference_is_not_no_send']=True
