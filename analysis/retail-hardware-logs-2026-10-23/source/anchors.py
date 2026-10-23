"""Pinned exact log format anchors and syntactic RIP references; no execution."""
from pathlib import Path
import os,json,hashlib,struct,bisect
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';assert hashlib.sha256(p.b).hexdigest()==PIN
patterns=['Motherboard:','Max Frequency:','Sockets:','vendor:','branding:'];anchors=[]
for pattern in patterns:
 pos=0
 while True:
  hit=p.b.find(pattern.encode(),pos)
  if hit<0:break
  pos=hit+1
  for sec in p.sections:
   if sec[4]<=hit<sec[4]+sec[3]:
    lo=p.b.rfind(b'\0',max(sec[4],hit-512),hit)+1;hi=p.b.find(b'\0',hit,min(hit+512,sec[4]+sec[3]));assert hi>=hit
    raw=p.b[lo:hi]
    if all(9<=v<=13 or 32<=v<127 for v in raw):anchors.append({'pattern':pattern,'rva':sec[2]+lo-sec[4],'file_offset':lo,'format_string':raw.decode('ascii'),'sha256':hashlib.sha256(raw+b'\0').hexdigest()})
r,s=p.dirs[3];bounds=sorted(struct.unpack('<III',p.read(r+i,12))[:2] for i in range(0,s,12));starts=[a for a,b in bounds]
def owner(a):
 j=bisect.bisect_right(starts,a)-1;return list(bounds[j]) if j>=0 and a<bounds[j][1] else None
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;refs={};chunk=4*1024*1024
peoff=struct.unpack_from('<I',p.b,0x3c)[0];op=peoff+24;st=op+struct.unpack_from('<H',p.b,peoff+20)[0]
for idx,sec in enumerate(p.sections):
 flags=struct.unpack_from('<I',p.b,st+idx*40+36)[0]
 if not flags&0x20000000:continue
 raw=p.b[sec[4]:sec[4]+min(sec[1],sec[3])]
 for off in range(0,len(raw),chunk):
  data=raw[off:off+chunk+15];n=len(data);core=min(chunk,len(raw)-off);rva=sec[2]+off
  if n<4:continue
  pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=data,strides=(1,));arr=np.frombuffer(data,dtype=np.uint8);mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
  for tail in [0,1,2,4,8]:
   dest=rva+pos+4+tail+disp;match=np.zeros(n-3,dtype=bool)
   for a in anchors:match|=dest==a['rva']
   for q0 in np.flatnonzero(mod&match):
    q=int(q0)
    for begin in range(max(0,q-11),q-1):
     if begin>=core:continue
     i=next(md.disasm(data[begin:begin+15],rva+begin,count=1),None)
     if i is None or i.disp_size!=4 or begin+i.disp_offset!=q or begin+i.size!=q+4+tail:continue
     for o in i.operands:
      if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
       target=i.address+i.size+o.mem.disp
       if any(target==a['rva'] for a in anchors):refs[(i.address,i.bytes.hex())]={'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'target_rva':target,'disp_offset':i.disp_offset,'pdata_owner':owner(i.address)}
# Match DIR64-backed pointers to exact string starts.
ptrs=[];r,size=p.dirs[5];cursor=0
while cursor<size:
 page,bs=struct.unpack('<II',p.read(r+cursor,8));assert bs>=8 and bs%2==0 and cursor+bs<=size
 for k in range(8,bs,2):
  e=p.u(r+cursor+k,'<H')
  if e>>12!=10:continue
  slot=page+(e&4095);target=p.u(slot,'<Q')-p.base
  if any(target==a['rva'] for a in anchors):ptrs.append({'slot_rva':slot,'target_rva':target})
 cursor+=bs
result={'sha256':PIN,'anchors':anchors,'syntactic_rip_references':sorted(refs.values(),key=lambda x:x['rva']),'relocation_backed_string_pointers':ptrs,'limits':'Exact string starts only; offset references, computed addresses and runtime pointers may be missed. A syntactic instruction/pdata owner is not a proven reachable use or hardware collector.'}
(D/'reports/anchors.json').write_text(json.dumps(result,indent=2)+'\n')
print('anchors',len(anchors),'RIP candidates',len(refs),'DIR64 pointers',len(ptrs))
for a in anchors:print(hex(a['rva']),repr(a['format_string']))
for x in result['syntactic_rip_references']:print(hex(x['rva']),x['asm'],'target',hex(x['target_rva']),'owner',x['pdata_owner'])
