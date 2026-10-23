"""Offline import/IAT reference inventory. No input binary is executed or patched."""
from pathlib import Path
import json,struct,hashlib,bisect,re
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
from pe_manual import PE
D=Path(__file__).resolve().parents[1]
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
names=['send','recv','sendto','recvfrom','WSASend','WSARecv','WSASendTo','WSARecvFrom','connect','WSAConnect','WSASocketW','socket','GetProcAddress','LoadLibraryA','LoadLibraryW','GetAddrInfoW','WinHttpSendRequest']
allrows=[]
for fn in ['Wow.exe','wow_loader.dll','libxell.dll']:
 p=PE(Path('/data/wlab-inputs')/fn);imports=[]
 for d in p.imports():
  for e in d['entries']:imports.append(dict(kind='normal',dll=d['dll'],**e))
 r,sz=p.dirs[13]
 if r:
  for off in range(0,sz,32):
   vals=struct.unpack('<8I',p.read(r+off,32))
   if not any(vals):break
   attr,name,handle,iat,intab,bound,unload,stamp=vals;assert attr==1
   for i in range(65536):
    v=p.u(intab+i*8,'<Q')
    if not v:break
    imports.append(dict(kind='delay',dll=p.text(name),slot_rva=iat+i*8,ordinal=v&65535 if v>>63 else None,literal_name=None if v>>63 else p.text(v+2)))
 slots={x['slot_rva']:x for x in imports};targets=set(slots)
 sec=[];peoff=struct.unpack_from('<I',p.b,0x3c)[0];op=peoff+24;osh=struct.unpack_from('<H',p.b,peoff+20)[0]
 for j,(name,vs,va,rs,ro) in enumerate(p.sections):sec.append(dict(name=name,rva=va,raw_size=rs,file_offset=ro,executable=bool(struct.unpack_from('<I',p.b,op+osh+j*40+36)[0]&0x20000000)))
 rd,size=p.dirs[3];bounds=sorted(struct.unpack('<III',p.read(rd+i,12))[:2] for i in range(0,size,12));starts=[a for a,b in bounds]
 def owner(x):
  q=bisect.bisect_right(starts,x)-1
  return list(bounds[q]) if q>=0 and x<bounds[q][1] else None
 refs={};chunk=2*1024*1024
 for s in sec:
  if not s['executable']:continue
  raw=p.read(s['rva'],s['raw_size'])
  for off in range(0,len(raw),chunk):
   b=raw[off:off+chunk+15];n=len(b);core=min(chunk,len(raw)-off);rva=s['rva']+off
   if n<4 or not targets:continue
   pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=b,strides=(1,));arr=np.frombuffer(b,dtype=np.uint8);mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
   for tail in [0,1,2,4,8]:
    dest=rva+pos+4+tail+disp;mask=mod&(dest>=min(targets))&(dest<=max(targets))
    for q0 in np.flatnonzero(mask):
     q=int(q0)
     if int(dest[q]) not in targets:continue
     for begin in range(max(0,q-11),q-1):
      if begin>=core:continue
      i=next(md.disasm(b[begin:begin+15],rva+begin,count=1),None)
      if i is None or i.disp_size!=4 or begin+i.disp_offset!=q or begin+i.size!=q+4+tail:continue
      for opnd in i.operands:
       if opnd.type==X86_OP_MEM and opnd.mem.base==X86_REG_RIP:
        target=i.address+i.size+opnd.mem.disp
        if target in targets:refs[i.address,i.bytes.hex()]=dict(rva=i.address,bytes=i.bytes.hex(),asm=i.mnemonic+' '+i.op_str,slot_rva=target,import_entry=slots[target],pdata_owner=owner(i.address))
 strings=[]
 for nm in names:
  for enc in ['ascii','utf-16le']:
   pat=nm.encode(enc)+(b'\0' if enc=='ascii' else b'\0\0');hits=[];at=0
   while True:
    at=p.b.find(pat,at)
    if at<0:break
    # Exact token left boundary; do not count WSASend as send or prefixes.
    left=p.b[max(0,at-(2 if enc=='utf-16le' else 1)):at]
    if not (left and (chr(left[0]).isalnum() or left[0]==95)):
     s=next((s for s in sec if s['file_offset']<=at and at+len(pat)<=s['file_offset']+s['raw_size']),None)
     hits.append(dict(file_offset=at,rva=s['rva']+at-s['file_offset'] if s else None,section=s['name'] if s else None))
    at+=1
   if hits:strings.append(dict(name=nm,encoding=enc,matches=hits))
 row=dict(binary=fn,sha256=hashlib.sha256(p.b).hexdigest(),base=p.base,sections=sec,imports=imports,rip_candidates=sorted(refs.values(),key=lambda x:x['rva']),api_name_strings=strings)
 allrows.append(row)
 print(fn,'imports',len(imports),'RIP candidates',len(refs),'API string groups',len(strings),flush=True)
(D/'reports/inventory.json').write_text(json.dumps(allrows,indent=2)+'\n')
