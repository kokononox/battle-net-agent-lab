"""Bounded BIOS-format xref expansion. Numerical/decoder hits are not runtime uses."""
from pathlib import Path
import os,json,hashlib,struct,bisect
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';assert hashlib.sha256(p.b).hexdigest()==PIN
bios=0x42b2268;fmt='Motherboard: "%s" by "%s" (BIOS:%s version:%s date:%s)';assert p.read(bios,len(fmt)+1)==fmt.encode()+b'\0'
spans=[('bios_format_bytes',bios,bios+len(fmt)+1),('hardware_log_two_pages',0x42b2000,0x42b4000),('positive_control_global_page',0x4ad5000,0x4ad6000)]
r,s=p.dirs[3];bounds=sorted(struct.unpack('<III',p.read(r+i,12))[:2] for i in range(0,s,12));starts=[a for a,b in bounds]
def owner(a):
 j=bisect.bisect_right(starts,a)-1;return list(bounds[j]) if j>=0 and a<bounds[j][1] else None
pe=struct.unpack_from('<I',p.b,0x3c)[0];st=pe+24+struct.unpack_from('<H',p.b,pe+20)[0];sections=[]
for i,sec in enumerate(p.sections):
 flags=struct.unpack_from('<I',p.b,st+i*40+36)[0];sections.append({'name':sec[0],'rva':sec[2],'virtual_size':sec[1],'raw_size':sec[3],'file_offset':sec[4],'executable':bool(flags&0x20000000)})
def slotinfo(rva):
 sec=next((s for s in sections if s['rva']<=rva<s['rva']+s['raw_size']),None)
 return {'section':sec['name'] if sec else None,'executable':sec['executable'] if sec else False,'pdata_owner':owner(rva)}
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;refs={};chunk=4*1024*1024
for sec in sections:
 if not sec['executable']:continue
 raw=p.read(sec['rva'],min(sec['virtual_size'],sec['raw_size']))
 for off in range(0,len(raw),chunk):
  data=raw[off:off+chunk+15];n=len(data);core=min(chunk,len(raw)-off);rva=sec['rva']+off
  if n<4:continue
  pos=np.arange(n-3,dtype=np.int64);disp=np.ndarray((n-3,),dtype='<i4',buffer=data,strides=(1,));arr=np.frombuffer(data,dtype=np.uint8);mod=np.zeros(n-3,dtype=bool);mod[1:]=(arr[:n-4]&0xc7)==5
  for tail in [0,1,2,4,8]:
   dest=rva+pos+4+tail+disp;match=np.zeros(n-3,dtype=bool)
   for _,lo,hi in spans:match|=(dest>=lo)&(dest<hi)
   for q0 in np.flatnonzero(mod&match):
    q=int(q0)
    for begin in range(max(0,q-11),q-1):
     if begin>=core:continue
     ins=next(md.disasm(data[begin:begin+15],rva+begin,count=1),None)
     if ins is None or ins.disp_size!=4 or begin+ins.disp_offset!=q or begin+ins.size!=q+4+tail:continue
     for op in ins.operands:
      if op.type!=X86_OP_MEM or op.mem.base!=X86_REG_RIP:continue
      target=ins.address+ins.size+op.mem.disp;labels=[name for name,lo,hi in spans if lo<=target<hi]
      if labels:refs[(ins.address,ins.bytes.hex())]={'rva':ins.address,'bytes':ins.bytes.hex(),'asm':ins.mnemonic+' '+ins.op_str,'target_rva':target,'disp_offset':ins.disp_offset,'target_spans':labels,'pdata_owner':owner(ins.address)}
# All-byte-alignment literal representations and self-relative DWORDs to BIOS string bytes only.
literals=[];selfrefs=[]
for sec in sections:
 raw=p.read(sec['rva'],sec['raw_size'])
 for off in range(0,len(raw),chunk):
  data=raw[off:off+chunk+8];core=min(chunk,len(raw)-off);rva=sec['rva']+off
  if len(data)>=4:
   val=np.ndarray((len(data)-3,),dtype='<u4',buffer=data,strides=(1,));q=np.arange(len(val),dtype=np.int64);signed=val.view('<i4').astype(np.int64)
   for label,lo in [('rva32',bios),('file_offset32',p.loc(bios,len(fmt)+1)['file_offset'])]:
    for idx in np.flatnonzero((val>=lo)&(val<lo+len(fmt)+1)&(q<core)):
     idx=int(idx);literals.append({'encoding':label,'slot_rva':rva+idx,'target_byte_offset':int(val[idx])-lo,'raw_hex':data[idx:idx+4].hex(),**slotinfo(rva+idx)})
   for bias in [0,4]:
    target=rva+q+bias+signed
    for idx in np.flatnonzero((target>=bios)&(target<bios+len(fmt)+1)&(q<core)):
     idx=int(idx);selfrefs.append({'slot_rva':rva+idx,'basis':'field_address' if bias==0 else 'field_end','target_rva':int(target[idx]),'raw_hex':data[idx:idx+4].hex(),**slotinfo(rva+idx)})
  if len(data)>=8:
   v=np.ndarray((len(data)-7,),dtype='<u8',buffer=data,strides=(1,))
   for idx in np.flatnonzero((v>=p.base+bios)&(v<p.base+bios+len(fmt)+1)):
    idx=int(idx)
    if idx<core:literals.append({'encoding':'preferred_va64','slot_rva':rva+idx,'target_byte_offset':int(v[idx])-p.base-bios,'raw_hex':data[idx:idx+8].hex(),**slotinfo(rva+idx)})
relocs=[];r,s=p.dirs[5];cursor=0
while cursor<s:
 page,n=struct.unpack('<II',p.read(r+cursor,8));assert n>=8 and n%2==0 and cursor+n<=s
 for i in range(8,n,2):
  v=p.u(r+cursor+i,'<H')
  if v>>12!=10:continue
  slot=page+(v&4095);target=p.u(slot,'<Q')-p.base;labels=[name for name,lo,hi in spans if lo<=target<hi]
  if labels:relocs.append({'slot_rva':slot,'target_rva':target,'target_spans':labels,**slotinfo(slot)})
 cursor+=n
result={'sha256':PIN,'image_base':p.base,'bios_rva':bios,'bios_format':fmt,'spans':[{'name':n,'begin':a,'end':b} for n,a,b in spans],'sections':sections,'rip_candidates':sorted(refs.values(),key=lambda x:x['rva']),'bios_literal_candidates':literals,'bios_self_relative_dword_candidates':selfrefs,'relocation_pointer_candidates':relocs,'limits':'RIP and scalar numerical matches are candidates, not confirmed instructions or semantic data references. Only listed encodings and bounded address ranges were searched; no arbitrary key/encoding or runtime transformation was inferred.'}
assert any(x['rva']==0x1da9b4 and x['target_rva']==0x4ad5f38 for x in refs.values()),'known control MOV must be detected'
(D/'reports/discovery.json').write_text(json.dumps(result,indent=2)+'\n')
print('RIP candidates',len(refs),'BIOS literals',len(literals),'self-relative dwords',len(selfrefs),'relocation pointers',len(relocs))
for x in result['rip_candidates']:
 if 'positive_control_global_page' not in x['target_spans']:print('RIP',hex(x['rva']),x['asm'],hex(x['target_rva']),x['pdata_owner'])
for x in literals:print('LITERAL',x)
for x in selfrefs:print('SELFREL',x)
