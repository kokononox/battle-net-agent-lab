"""Version-number-independent metadata readers. Unknown binary layouts fail closed.
Labels and recipes are metadata only, never executed or opened as file paths.
"""
import hashlib,struct
from release_core import need,InvalidRelease
ZERO=bytes(16)

def parse_install(raw):
 need(type(raw)is bytes and 10<=len(raw)<=4*1024**2,'install_byte_limit');at=0
 def take(n):
  nonlocal at
  need(type(n)is int and 0<=n<=len(raw)-at,'install_truncated');r=raw[at:at+n];at+=n;return r
 def text(limit,encoding):
  pos=raw.find(b'\0',at,min(len(raw),at+limit+1));need(pos>at,'install_string');s=take(pos-at).decode(encoding);take(1);need(all(ord(c)>=32 and ord(c)!=127 for c in s),'install_string_controls');return s
 h=take(10);magic,v,kw,nt,n=struct.unpack('>2sBBHI',h);need(magic==b'IN' and v==1 and kw==16,'install_unknown_layout');need(nt<=256 and 0<n<=1000000,'install_geometry');width=(n+7)//8;need(nt*(width+3)+n*21<=len(raw)-10,'install_bounds');tags=[]
 for i in range(nt):tags.append((i,text(64,'ascii'),int.from_bytes(take(2),'big'),take(width)))
 entries=[]
 for i in range(n):
  label=text(4096,'utf-8');key=take(16);size=int.from_bytes(take(4),'big');need(key!=ZERO,'install_zero_ckey');entries.append((i,label,key,size))
 need(at==len(raw),'install_trailing');return tags,entries

class DownloadReader:
 def __init__(self,f,size):
  self.f=f;self.size=size;h=f.read(11);need(len(h)==11 and h[:5]==b'DL\x01\x10\x00','download_unknown_layout');self.n=int.from_bytes(h[5:9],'big');self.nt=int.from_bytes(h[9:11],'big');need(0<self.n<=20000000 and self.nt<=256 and 11+self.n*22+self.nt*((self.n+7)//8+3)<=size,'download_geometry')
 def records(self):
  self.f.seek(11)
  for start in range(0,self.n,8192):
   n=min(8192,self.n-start);raw=self.f.read(n*22);need(len(raw)==n*22,'download_truncated')
   for j in range(n):
    r=raw[j*22:(j+1)*22];size=int.from_bytes(r[16:21],'big');need(r[:16]!=ZERO and size>0,'download_invalid_record');yield start+j,r[:16],size,r[21]
 def tags(self):
  self.f.seek(11+self.n*22);width=(self.n+7)//8
  for i in range(self.nt):
   name=bytearray()
   while True:
    c=self.f.read(1);need(bool(c),'download_tag_truncated')
    if c==b'\0':break
    name+=c;need(len(name)<=64,'download_tag_name_limit')
   need(bool(name) and all(32<=c<127 for c in name),'download_tag_name');kind=self.f.read(2);bits=self.f.read(width);need(len(kind)==2 and len(bits)==width,'download_bitmap_truncated');yield i,name.decode('ascii'),int.from_bytes(kind,'big'),bits
  need(self.f.tell()==self.size and not self.f.read(1),'download_trailing')

class EncodingReader:
 def __init__(self,f,size):
  self.f=f;self.size=size;f.seek(0);h=f.read(22);need(len(h)==22 and h[:5]==b'EN\x01\x10\x10' and h[17]==0,'encoding_unknown_layout');self.cs=int.from_bytes(h[5:7],'big')*1024;self.es=int.from_bytes(h[7:9],'big')*1024;self.cn=int.from_bytes(h[9:13],'big');self.en=int.from_bytes(h[13:17],'big');ss=int.from_bytes(h[18:22],'big');need(1024<=self.cs<=65536 and 1024<=self.es<=65536 and 0<self.cn<=500000 and 0<self.en<=500000 and 0<ss<=16*1024**2,'encoding_geometry')
  self.cp=22+ss+32*self.cn;ei=self.cp+self.cs*self.cn;self.ep=ei+32*self.en;self.stop=self.ep+self.es*self.en;need(self.stop<=size,'encoding_geometry_bounds');raw=f.read(ss);need(len(raw)==ss and raw.endswith(b'\0'),'encoding_spec_termination');self.specs=raw[:-1].decode('ascii').split('\0');need(len(self.specs)<=500000,'encoding_spec_count');self.cindex=self.index(22+ss,self.cn);self.eindex=self.index(ei,self.en);f.seek(self.stop);tail=f.read();need(len(tail)==size-self.stop,'encoding_tail_truncated');self.tail={'bytes':len(tail),'sha256':hashlib.sha256(tail).hexdigest(),'semantically_parsed':False}
 def index(self,at,n):
  self.f.seek(at);raw=self.f.read(n*32);need(len(raw)==n*32,'encoding_index_truncated');rows=[(raw[i:i+16],raw[i+16:i+32]) for i in range(0,len(raw),32)];need(all(k!=ZERO for k,h in rows) and all(rows[i-1][0]<rows[i][0] for i in range(1,n)),'encoding_index_order');return rows
 def pages(self,which):
  rows,width,at=(self.cindex,self.cs,self.cp) if which=='c' else (self.eindex,self.es,self.ep)
  for i,(first,md) in enumerate(rows):
   self.f.seek(at+i*width);raw=self.f.read(width);need(len(raw)==width and hashlib.md5(raw).digest()==md,'encoding_page_hash');yield raw,first,rows[i+1][0] if i+1<len(rows) else None
 def content(self):
  last=None
  for raw,first,next_key in self.pages('c'):
   pos=0;seen=False
   while pos<len(raw):
    n=raw[pos]
    if not n:need(not any(raw[pos:]),'encoding_c_padding');break
    stop=pos+22+16*n;need(stop<=len(raw),'encoding_c_bounds');key=raw[pos+6:pos+22];size=int.from_bytes(raw[pos+1:pos+6],'big');links=tuple(raw[i:i+16] for i in range(pos+22,stop,16));need(key!=ZERO and (last is None or last<key) and (seen or key==first) and (next_key is None or key<next_key),'encoding_c_order');need(all(k!=ZERO for k in links) and len(set(links))==n,'encoding_c_links');yield key,size,links;seen=True;last=key;pos=stop
   need(seen,'encoding_c_empty_page')
 def encoded(self):
  last=None
  for raw,first,next_key in self.pages('e'):
   pos=0;seen=False
   while pos+25<=len(raw):
    key=raw[pos:pos+16]
    if key==ZERO:need(raw[pos+16:pos+20] in (bytes(4),b'\xff'*4) and not any(raw[pos+20:]),'encoding_e_terminator');pos=len(raw);break
    idx=int.from_bytes(raw[pos+16:pos+20],'big');size=int.from_bytes(raw[pos+20:pos+25],'big');need((last is None or last<key) and (seen or key==first) and (next_key is None or key<next_key),'encoding_e_order');need(idx<len(self.specs) and size>0,'encoding_e_record');yield key,size,idx;last=key;seen=True;pos+=25
   need(seen and not any(raw[pos:]),'encoding_e_padding')
