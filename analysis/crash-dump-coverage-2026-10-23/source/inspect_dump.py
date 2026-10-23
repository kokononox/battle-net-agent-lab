"""Read-only, bounded minidump coverage inspection; no input code execution."""
from pathlib import Path
import zipfile,struct,hashlib,json,re,os
D=Path(__file__).resolve().parents[1]
(D/'reports').mkdir(exist_ok=True);(D/'work').mkdir(exist_ok=True)
Z=Path(os.environ.get('ARCHIVE','Errors.zip'))
TARGETS=[('merge_candidate',0x1b14120,0x1b14138),('creator_candidate',0x1b11190,0x1b111fe),('parse_fallback_candidate',0x33068c0,0x33069b4)]
def sha(b):return hashlib.sha256(b).hexdigest()
class Dump:
 def __init__(self,b):
  self.b=b;assert b[:4]==b'MDMP';self.streams={};n,off=struct.unpack_from('<II',self.read(8,8));assert n<1000
  for i in range(n):
   t,size,rva=struct.unpack('<III',self.read(off+12*i,12))
   if t==0:
    assert size==0 and rva==0;continue
   assert t not in self.streams;self.read(rva,size);self.streams[t]=(rva,size)
 def read(self,o,n):
  assert 0<=o<=len(self.b) and 0<=n<=len(self.b)-o
  return self.b[o:o+n]
 def string(self,r):
  n=struct.unpack('<I',self.read(r,4))[0];assert n<65536 and n%2==0
  return self.read(r+4,n).decode('utf-16le',errors='replace')
 def modules(self):
  if 4 not in self.streams:return []
  r,s=self.streams[4];n=struct.unpack('<I',self.read(r,4))[0];assert 4+108*n<=s;rows=[]
  for i in range(n):
   q=r+4+108*i;base,size,checksum,stamp,name=struct.unpack('<QIIII',self.read(q,24));fixed=struct.unpack('<13I',self.read(q+24,52));cvsz,cvr=struct.unpack('<II',self.read(q+76,8));cv=self.read(cvr,cvsz) if cvsz else b''
   rows.append({'name':self.string(name).replace('\\','/').rsplit('/',1)[-1],'base':base,'size':size,'timestamp':stamp,'checksum':checksum,'file_version':f'{fixed[2]>>16}.{fixed[2]&65535}.{fixed[3]>>16}.{fixed[3]&65535}','cv_sha256':sha(cv) if cv else None,'cv_signature':cv[:4].decode('ascii',errors='replace')})
  return rows
 def ranges(self):
  rows=[]
  if 5 in self.streams:
   r,s=self.streams[5];n=struct.unpack('<I',self.read(r,4))[0];assert n<1000000 and 4+16*n<=s
   for i in range(n):
    a,n,o=struct.unpack('<QII',self.read(r+4+16*i,16));self.read(o,n);rows.append((a,n,o,'MemoryList'))
  if 9 in self.streams:
   r,s=self.streams[9];count,o=struct.unpack('<QQ',self.read(r,16));assert count<1000000 and 16+16*count<=s
   for i in range(count):
    a,n=struct.unpack('<QQ',self.read(r+16+16*i,16));self.read(o,n);rows.append((a,n,o,'Memory64List'));o+=n
  return rows
 def memory_infos(self):
  if 16 not in self.streams:return []
  r,s=self.streams[16];header,entry,n=struct.unpack('<IIQ',self.read(r,16));assert header>=16 and entry>=48 and n<1000000 and header+entry*n<=s;rows=[]
  for i in range(n):
   a,alloc,ap,_,size,state,prot,typ,_=struct.unpack('<QQIIQIIII',self.read(r+header+entry*i,48));rows.append({'base':a,'allocation_base':alloc,'size':size,'state':state,'protect':prot,'type':typ})
  return rows
 def memory(self,addr,n,ranges):
  out=bytearray();cursor=addr;pieces=[]
  while cursor<addr+n:
   found=[x for x in ranges if x[0]<=cursor<x[0]+x[1]]
   if not found:return None,pieces
   # Refuse inconsistent duplicate ranges.
   take=min(addr+n-cursor,min(a+sz-cursor for a,sz,off,t in found))
   chunks=[self.read(off+cursor-a,take) for a,sz,off,t in found];assert all(c==chunks[0] for c in chunks)
   out+=chunks[0];pieces.append({'address':cursor,'bytes':take});cursor+=take
  return bytes(out),pieces
if __name__=='__main__':
 with zipfile.ZipFile(Z) as z:
  members=z.infolist();assert len(members)<100 and sum(x.file_size for x in members)<200*1024*1024
  result={'archive_sha256':sha(Z.read_bytes()),'dumps':[],'text_relevant_lines':[]}
  for m in members:
   b=z.read(m);assert len(b)==m.file_size
   if m.filename.endswith('.txt'):
    text=b.decode('utf-8-sig',errors='replace')
    # Only narrow build/crash markers, not account/path/register/memory dumps.
    result['text_relevant_lines']=[s.strip()[:250] for s in text.splitlines() if re.match(r'^\s*(?:World of Warcraft:|<Version>|<Exception.BuildNumber>|<Exception.Branch>|<Executable>)',s,re.I)]
    (D/'work/crash-text.txt').write_text(text);continue
   if not m.filename.endswith('.dmp'):continue
   md=Dump(b);mods=md.modules();ranges=md.ranges();infos=md.memory_infos();wow=[x for x in mods if x['name'].lower()=='wow.exe'];assert len(wow)<=1
   row={'name':m.filename,'size_bytes':len(b),'sha256':sha(b),'streams':[{'type':t,'size':v[1]} for t,v in sorted(md.streams.items())],'modules_count':len(mods),'relevant_modules':[x for x in mods if x['name'].lower() in ('wow.exe','wow_loader.dll','libxell.dll')],'memory_range_count':len(ranges),'stored_memory_bytes':sum(x[1] for x in ranges),'targets':[]}
   if 6 in md.streams:
    r,s=md.streams[6];assert s>=32;thread,_,code,flags,record,address=struct.unpack('<IIIIQQ',md.read(r,32));row['exception']={'code':hex(code),'address':hex(address),'wow_rva':hex(address-wow[0]['base']) if wow and wow[0]['base']<=address<wow[0]['base']+wow[0]['size'] else None}
   if wow:
    for role,start,end in TARGETS:
     address=wow[0]['base']+start;raw,pieces=md.memory(address,end-start,ranges);matches=[x for x in infos if x['base']<=address<x['base']+x['size']]
     row['targets'].append({'role':role,'rva':hex(start),'address':hex(address),'length':end-start,'fully_present':raw is not None,'sha256':sha(raw) if raw is not None else None,'available_prefix_bytes':sum(x['bytes'] for x in pieces),'memory_info':matches})
    header,pieces=md.memory(wow[0]['base'],4096,ranges);row['wow_header_present']=header is not None
    if header:(D/'work'/f'{m.filename}.header.bin').write_bytes(header)
   (D/'work'/m.filename).write_bytes(b);result['dumps'].append(row)
 (D/'reports/inspection.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2))
