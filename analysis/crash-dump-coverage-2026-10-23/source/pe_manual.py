"""Standard-library manual PE reader, reused from startup review 8d0ff18. No binary execution."""
import struct
class PE:
 def __init__(self,path):
  self.b=path.read_bytes();b=self.b
  assert b[:2]==b'MZ';o=struct.unpack_from('<I',b,0x3c)[0];assert b[o:o+4]==b'PE\0\0'
  machine,n,_,_,_,sz,_=struct.unpack_from('<HHIIIHH',b,o+4);assert machine==0x8664
  opt=o+24;assert struct.unpack_from('<H',b,opt)[0]==0x20b
  self.base=struct.unpack_from('<Q',b,opt+24)[0];self.ep=struct.unpack_from('<I',b,opt+16)[0]
  self.dirs=[struct.unpack_from('<II',b,opt+112+i*8) for i in range(16)];self.sections=[]
  for i in range(n):
   s=opt+sz+i*40;name=b[s:s+8].rstrip(b'\0').decode();vs,r,rs,ro=struct.unpack_from('<IIII',b,s+8)
   self.sections.append((name,vs,r,rs,ro))
 def loc(self,r,n=1):
  for name,vs,va,rs,ro in self.sections:
   d=r-va
   if d>=0 and d+n<=max(vs,rs):return {'section':name,'file_backed':d+n<=rs,'file_offset':ro+d if d+n<=rs else None,'zero_filled_virtual_tail':d+n>rs and d+n<=vs}
  raise AssertionError('RVA unmapped')
 def read(self,r,n):
  l=self.loc(r,n);assert l['file_backed'];o=l['file_offset'];assert o+n<=len(self.b);return self.b[o:o+n]
 def u(self,r,fmt):return struct.unpack(fmt,self.read(r,struct.calcsize(fmt)))[0]
 def text(self,r):
  out=bytearray()
  for i in range(4096):
   c=self.read(r+i,1)
   if c==b'\0':return out.decode()
   out+=c
  raise AssertionError('Unterminated name')
 def imports(self):
  start,size=self.dirs[1];rows=[]
  if not start:return rows
  for k in range(4096):
   r=start+k*20;d=struct.unpack('<IIIII',self.read(r,20))
   if not any(d):return rows
   oft,_,_,name,ft=d;entries=[]
   for i in range(65536):
    v=self.u((oft or ft)+i*8,'<Q')
    if not v:break
    ordinal=(v&0xffff) if v>>63 else None
    entries.append({'ordinal':ordinal,'literal_name':None if ordinal is not None else self.text(v+2),'slot_rva':ft+i*8})
   else:raise AssertionError('Unterminated thunk')
   rows.append({'dll':self.text(name),'descriptor_file_offset':self.loc(r,20)['file_offset'],'first_thunk':ft,'original_first_thunk':oft,'entries':entries})
  raise AssertionError('Unterminated descriptors')
 def tls(self):
  start,size=self.dirs[9];out=[]
  if not start:return out
  va=self.u(start+24,'<Q')
  if not va:return out
  arr=va-self.base
  for i in range(64):
   v=self.u(arr+i*8,'<Q')
   if not v:return out
   out.append({'slot_rva':arr+i*8,'callback_rva':v-self.base})
  raise AssertionError('Unterminated TLS')
 def exports(self):
  start,size=self.dirs[0];out=[]
  if not start:return out
  raw=self.read(start,40);base,n,names,funcs=struct.unpack_from('<IIII',raw,16)
  for i in range(n):
   r=self.u(funcs+4*i,'<I')
   if r:out.append({'ordinal':base+i,'rva':r,'forwarder':self.text(r) if start<=r<start+size else None})
  return out
