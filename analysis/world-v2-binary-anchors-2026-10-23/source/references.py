"""References to normalized V2 banners; candidates are not proven runtime uses."""
from pathlib import Path
import os,struct,json,hashlib,bisect
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
from pe_manual import PE
D=Path(__file__).resolve().parents[1];r=json.loads((D/'reports/discovery.json').read_text());p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');assert hashlib.sha256(p.b).hexdigest()==r['binaries'][0]['sha256']
a=[]
for x in r['binaries'][0]['strings']:
 if x['pattern']=='WORLD OF WARCRAFT CONNECTION' and x['encoding']=='ascii':
  for y in x['matches']:
   text=y['ascii_container'];assert text.endswith(' - V2');at=y['rva'];assert p.read(at,len(text)+1)==text.encode()+b'\0';a.append({'role':'server_banner' if 'SERVER TO CLIENT' in text else 'client_banner','rva':at,'text':text,'length_including_nul':len(text)+1,'sha256':hashlib.sha256(text.encode()+b'\0').hexdigest()})
assert {x['rva'] for x in a}=={0x414f098,0x414f0d0}
spans=[(x['role'],x['rva'],x['rva']+x['length_including_nul']) for x in a]+[('adjacent_banner_page',0x414f000,0x4150000),('positive_control_global_page',0x4ad5000,0x4ad6000)]
rd,sz=p.dirs[3];bounds=sorted(struct.unpack('<III',p.read(rd+i,12))[:2] for i in range(0,sz,12));starts=[x[0] for x in bounds]
def owner(x):
 j=bisect.bisect_right(starts,x)-1;return list(bounds[j]) if j>=0 and x<bounds[j][1] else None
sections=r['binaries'][0]['sections'];md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;refs={};chunk=4*1024*1024
for sec in sections:
 if not sec['executable']:continue
 raw=p.read(sec['rva'],sec['raw_size'])
 for off in range(0,len(raw),chunk):
  b=raw[off:off+chunk+15];n=len(b);core=min(chunk,len(raw)-off);rva=sec['rva']+off
  if n<4:continue
  pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=b,strides=(1,));arr=np.frombuffer(b,dtype=np.uint8);mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
  for tail in [0,1,2,4,8]:
   dest=rva+pos+4+tail+disp;match=np.zeros(n-3,dtype=bool)
   for _,lo,hi in spans:match|=(dest>=lo)&(dest<hi)
   for q0 in np.flatnonzero(mod&match):
    q=int(q0)
    for begin in range(max(0,q-11),q-1):
     if begin>=core:continue
     i=next(md.disasm(b[begin:begin+15],rva+begin,count=1),None)
     if i is None or i.disp_size!=4 or begin+i.disp_offset!=q or begin+i.size!=q+4+tail:continue
     for op in i.operands:
      if op.type!=X86_OP_MEM or op.mem.base!=X86_REG_RIP:continue
      target=i.address+i.size+op.mem.disp;labels=[name for name,lo,hi in spans if lo<=target<hi]
      if labels:refs[(i.address,i.bytes.hex())]={'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'target_rva':target,'target_spans':labels,'disp_offset':i.disp_offset,'pdata_owner':owner(i.address)}
ptrs=[];rd,sz=p.dirs[5];cur=0
while cur<sz:
 page,n=struct.unpack('<II',p.read(rd+cur,8));assert n>=8 and cur+n<=sz
 for j in range(8,n,2):
  e=p.u(rd+cur+j,'<H')
  if e>>12!=10:continue
  slot=page+(e&4095);target=p.u(slot,'<Q')-p.base;labels=[name for name,lo,hi in spans if lo<=target<hi]
  if labels:ptrs.append({'slot_rva':slot,'target_rva':target,'target_spans':labels})
 cur+=n
literals=[]
for anchor in a:
 for form,value in [('rva32',anchor['rva']),('preferred_va64',p.base+anchor['rva'])]:
  pattern=struct.pack('<I' if form=='rva32' else '<Q',value);off=0
  while True:
   off=p.b.find(pattern,off)
   if off<0:break
   sec=next((s for s in sections if s['file_offset']<=off and off+len(pattern)<=s['file_offset']+s['raw_size']),None)
   literals.append({'banner':anchor['role'],'encoding':form,'file_offset':off,'rva':sec['rva']+off-sec['file_offset'] if sec else None,'section':sec['name'] if sec else None});off+=1
assert any(x['rva']==0x1da9b4 and x['target_rva']==0x4ad5f38 for x in refs.values())
# Literal occurrences in loader code: accept only exact immediate boundaries as decoder candidates.
loader=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'wow_loader.dll');imms=[]
for x in r['binaries'][1]['literal_dword_search']:
 for m in x['matches']:
  if not m['executable_section']:continue
  q=m['rva'];found=[]
  for begin in range(q-14,q+1):
   i=next(md.disasm(loader.read(begin,15),begin,count=1),None)
   if i and i.imm_size==4 and begin+i.imm_offset==q and begin+i.size>=q+4:found.append({'rva':begin,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str})
  imms.append({'literal_rva':q,'literal_value':x['value'],'decoder_immediate_candidates':found,'network_semantics_proven':False})
result={'anchors':a,'target_spans':[{'name':n,'begin':lo,'end':hi} for n,lo,hi in spans],'rip_candidates':sorted(refs.values(),key=lambda x:x['rva']),'relocation_pointer_candidates':ptrs,'literal_banner_address_matches':literals,'loader_executable_literal_triage':imms,'limits':'RIP syntax and literal/pointer inventory do not prove runtime reachability. Banner normalization removes final wire newline and requires static NUL; no assumption about where newline is appended. Encoded/computed pointers, indirect dataflow and runtime-only code remain outside coverage.'}
(D/'reports/references.json').write_text(json.dumps(result,indent=2)+'\n');print('RIP',len(refs),'DIR64',len(ptrs),'literal addresses',len(literals))
for x in result['rip_candidates']:
 if 'positive_control_global_page' not in x['target_spans']:print('RIP',hex(x['rva']),x['asm'],hex(x['target_rva']),x['target_spans'],x['pdata_owner'])
for x in ptrs:print('PTR',hex(x['slot_rva']),hex(x['target_rva']),x['target_spans'])
print('literal',literals);print('loader immediates',imms)
