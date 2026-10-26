"""Pure offline codec functions copied unchanged from pinned G43. No networking."""
import hashlib,struct,zlib
MAX=1048576
class Rejected(ValueError):pass

def decode_blte(b,expected,ekey):
 if len(b)>MAX or len(b)<9 or b[:4]!=b'BLTE' or not 0<expected<=MAX:raise Rejected('blte_header')
 hs=int.from_bytes(b[4:8],'big')
 covered=b[:hs] if hs else b
 if hashlib.md5(covered).hexdigest()!=ekey:raise Rejected('ekey_mismatch')
 def chunk(data,limit):
  if not data:raise Rejected('chunk_empty')
  if data[:1]==b'N':plain=data[1:]
  elif data[:1]==b'Z':
   z=zlib.decompressobj();plain=z.decompress(data[1:],limit+1)
   if len(plain)>limit or z.unconsumed_tail or z.unused_data or not z.eof:raise Rejected('zlib_bounds_or_trailing')
  else:raise Rejected('unsupported_blte_mode') # Encrypted/recursive modes stay closed.
  if len(plain)>limit:raise Rejected('decoded_bound')
  return plain
 if not hs:
  plain=chunk(b[8:],expected)
  if len(plain)!=expected:raise Rejected('decoded_size')
  return plain
 if hs<12 or hs>len(b) or b[8]!=0x0f:raise Rejected('chunk_table_header')
 count=int.from_bytes(b[9:12],'big')
 if not 1<=count<=1024 or hs!=12+24*count:raise Rejected('chunk_count_or_table_size')
 p=hs;out=bytearray()
 for i in range(count):
  o=12+i*24;es,ds=struct.unpack_from('>II',b,o);md=b[o+8:o+24]
  if not es or ds>expected-len(out) or p+es>len(b):raise Rejected('chunk_size_bound')
  data=b[p:p+es];p+=es
  if hashlib.md5(data).digest()!=md:raise Rejected('chunk_hash')
  plain=chunk(data,ds)
  if len(plain)!=ds:raise Rejected('decoded_chunk_size')
  out.extend(plain)
 if p!=len(b) or len(out)!=expected:raise Rejected('blte_size_or_trailing')
 return bytes(out)

class Reader:
 def __init__(self,b):
  if len(b)>MAX:raise Rejected('manifest_bound')
  self.b=b;self.p=0
 def get(self,n):
  if n<0 or self.p+n>len(self.b):raise Rejected('truncated')
  x=self.b[self.p:self.p+n];self.p+=n;return x
 def num(self,n):return int.from_bytes(self.get(n),'big')
 def string(self):
  end=self.b.find(b'\0',self.p,min(len(self.b),self.p+4097))
  if end<0:raise Rejected('unterminated_string')
  x=self.get(end-self.p+1)[:-1].decode('utf-8','strict')
  if any(ord(c)<32 for c in x):raise Rejected('control_in_string')
  return x
 def done(self):
  if self.p!=len(self.b):raise Rejected('manifest_trailing')

def tags(r,nt,n):
 out=[]
 for _ in range(nt):
  name=r.string();typ=r.num(2);mask=r.get((n+7)//8)
  out.append({'name':name,'type':typ,'mask_hex':mask.hex()})
 return out

def parse_install(b):
 r=Reader(b)
 if r.get(2)!=b'IN' or r.num(1)!=1 or r.num(1)!=16:raise Rejected('install_header')
 nt,n=r.num(2),r.num(4)
 if nt>256 or n>10000:raise Rejected('install_count')
 ts=tags(r,nt,n);entries=[]
 for i in range(n):
  name=r.string();ckey=r.get(16).hex();size=r.num(4)
  if name.startswith(('/','\\')) or any(c in name.replace('\\','/').split('/') for c in ('.','..')) or ':' in name:raise Rejected('unsafe_install_path')
  entries.append({'index':i,'name':name,'ckey':ckey,'decoded_bytes':size})
 r.done();return {'signature':'IN','version':1,'entry_count':n,'tags':ts,'entries':entries}

def parse_download(b):
 r=Reader(b)
 if r.get(2)!=b'DL':raise Rejected('download_signature')
 version,hs,checksum,n,nt=r.num(1),r.num(1),r.num(1),r.num(4),r.num(2)
 if version not in (1,2,3) or hs!=16 or checksum not in (0,1) or n>10000 or nt>256:raise Rejected('download_header')
 flags=r.num(1) if version>=2 else 0;base=0
 if flags>4:raise Rejected('download_flags_bound')
 if version>=3:
  base=r.num(1)
  if r.get(3)!=b'\0\0\0':raise Rejected('download_reserved')
 es=[]
 for i in range(n):
  e={'index':i,'ekey':r.get(16).hex(),'encoded_bytes':r.num(5),'priority':r.num(1)-base}
  if checksum:e['checksum']=r.get(4).hex()
  if flags:e['flags_hex']=r.get(flags).hex()
  es.append(e)
 ts=tags(r,nt,n);r.done()
 return {'signature':'DL','version':version,'entry_count':n,'base_priority':base,'tags':ts,'entries':es}
