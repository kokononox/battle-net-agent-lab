"""References to NUL-delimited connection diagnostic strings; no input execution."""
from pathlib import Path
import os,struct,json,hashlib,bisect
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path('/data/wlab-inputs/Wow.exe'))
assert hashlib.sha256(p.b).hexdigest()=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
a=[]
sections=[];peoff=struct.unpack_from('<I',p.b,0x3c)[0];op=peoff+24;osh=struct.unpack_from('<H',p.b,peoff+20)[0]
for j,(name,vs,va,rs,ro) in enumerate(p.sections):sections.append(dict(name=name,rva=va,raw_size=rs,file_offset=ro,executable=bool(struct.unpack_from('<I',p.b,op+osh+j*40+36)[0]&0x20000000)))
for text in ['connect','WSAStartup','RouteResolutionWorkerThread','Send-triggered key update']:
 pat=text.encode()+b'\0';at=0
 while True:
  at=p.b.find(pat,at)
  if at<0:break
  if at==0 or p.b[at-1]==0:
   sec=next(s for s in sections if s['file_offset']<=at and at+len(pat)<=s['file_offset']+s['raw_size'])
   a.append(dict(role=text,rva=sec['rva']+at-sec['file_offset'],text=text,length_including_nul=len(pat)))
  at+=1
assert next(x['rva'] for x in a if x['role']=='connect')==0x42491d8
spans=[(x['role'],x['rva'],x['rva']+x['length_including_nul']) for x in a]+[('WSAStartup_numeric_string_record',0x3ea6d40,0x3ea6d50),('connect_adjacent_page',0x4249000,0x424a000),('positive_control_global_page',0x4ad5000,0x4ad6000)]
rd,sz=p.dirs[3];bounds=sorted(struct.unpack('<III',p.read(rd+i,12))[:2] for i in range(0,sz,12));starts=[x[0] for x in bounds]
def owner(x):
 j=bisect.bisect_right(starts,x)-1;return list(bounds[j]) if j>=0 and x<bounds[j][1] else None
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;refs={};chunk=4*1024*1024
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
   literals.append({'anchor':anchor['role'],'encoding':form,'file_offset':off,'rva':sec['rva']+off-sec['file_offset'] if sec else None,'section':sec['name'] if sec else None});off+=1
assert any(x['rva']==0x1da9b4 and x['target_rva']==0x4ad5f38 for x in refs.values())
result={'binary_sha256':hashlib.sha256(p.b).hexdigest(),'anchors':a,'target_spans':[{'name':n,'begin':lo,'end':hi} for n,lo,hi in spans],'rip_candidates':sorted(refs.values(),key=lambda x:x['rva']),'relocation_pointer_candidates':ptrs,'literal_anchor_address_matches':literals,'limits':'Syntactic references only; no runtime execution or encoded/computed pointer resolution. disp32 tails 0,1,2,4,8; file-backed executable sections only.'}
(D/'reports/references.json').write_text(json.dumps(result,indent=2)+'\n')
print('anchors',[(x['role'],hex(x['rva'])) for x in a]);print('RIP',len(refs),'DIR64',len(ptrs),'literals',len(literals))
for x in result['rip_candidates']:
 if 'positive_control_global_page' not in x['target_spans']:print('RIP',hex(x['rva']),x['asm'],hex(x['target_rva']),x['target_spans'],x['pdata_owner'])
for x in ptrs:print('PTR',hex(x['slot_rva']),hex(x['target_rva']),x['target_spans'])
print('literal',literals)
