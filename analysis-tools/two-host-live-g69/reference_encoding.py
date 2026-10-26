"""Bounded offline EN v1 decoder. No sockets, file execution, or ESpec evaluation."""
import hashlib,re,struct
class Rejected(ValueError):pass
MAX=1048576

def parse_encoding(b):
 if len(b)<22 or len(b)>MAX:raise Rejected('encoding_size_bound')
 magic,version,cksz,eksz,cpkb,epkb,ncp,nep,flags,eslen=struct.unpack('>2sBBBHHIIBI',b[:22])
 if (magic,version,cksz,eksz,flags)!=(b'EN',1,16,16,0):raise Rejected('encoding_header')
 if not 1<=cpkb<=64 or not 1<=epkb<=64 or not 1<=ncp<=128 or not 1<=nep<=128 or not 1<=eslen<=65536:raise Rejected('encoding_header_bounds')
 p=22
 def take(n):
  nonlocal p
  if n<0 or p+n>len(b):raise Rejected('encoding_truncated')
  v=b[p:p+n];p+=n;return v
 esdata=take(eslen)
 if not esdata.endswith(b'\0'):raise Rejected('espec_block_termination')
 especs=[x.decode('ascii','strict') for x in esdata[:-1].split(b'\0')]
 if not especs or any(not x or len(x)>4096 for x in especs):raise Rejected('espec_entry_bound')
 mappings=[];specs=[];pages=[];seenck=set();seenek=set();lastck=None;lastek=None
 def table(count):
  out=[];last=None
  for i in range(count):
   first=take(16);digest=take(16)
   if last is not None and first<=last:raise Rejected('page_index_not_sorted')
   last=first;out.append((first,digest))
  return out
 ctable=table(ncp)
 for i,(first,digest) in enumerate(ctable):
  data=take(cpkb*1024)
  if hashlib.md5(data).digest()!=digest:raise Rejected('ckey_page_hash')
  q=0;rows=0
  while q<len(data) and data[q]:
   count=data[q];q+=1
   if count>16 or q+5+16+count*16>len(data):raise Rejected('ckey_record_bound')
   size=int.from_bytes(data[q:q+5],'big');q+=5;ck=data[q:q+16];q+=16
   keys=[data[q+j*16:q+(j+1)*16].hex() for j in range(count)];q+=count*16
   if ck in seenck or lastck is not None and ck<=lastck or len(set(keys))!=len(keys):raise Rejected('ckey_duplicate_or_order')
   if rows==0 and ck!=first:raise Rejected('ckey_index_first_key')
   lastck=ck;seenck.add(ck);mappings.append({'ckey':ck.hex(),'decoded_bytes':size,'ekeys':keys});rows+=1
  if not rows or any(data[q:]):raise Rejected('ckey_page_padding')
  pages.append({'kind':'ckey','index':i,'bytes':len(data),'records':rows,'first_key':first.hex(),'md5':digest.hex(),'verified':True})
 etable=table(nep)
 for i,(first,digest) in enumerate(etable):
  data=take(epkb*1024)
  if hashlib.md5(data).digest()!=digest:raise Rejected('ekey_page_hash')
  q=0;rows=0
  while q+25<=len(data) and any(data[q:q+16]):
   ek=data[q:q+16];idx=int.from_bytes(data[q+16:q+20],'big');size=int.from_bytes(data[q+20:q+25],'big');q+=25
   if ek in seenek or lastek is not None and ek<=lastek:raise Rejected('ekey_duplicate_or_order')
   if rows==0 and ek!=first:raise Rejected('ekey_index_first_key')
   if idx>=len(especs):raise Rejected('espec_index_bound')
   lastek=ek;seenek.add(ek);specs.append({'ekey':ek.hex(),'espec_index':idx,'encoded_bytes':size});rows+=1
  terminal=False
  if data[q:q+25]==b'\0'*16+b'\xff'*4+b'\0'*5:
   if i!=nep-1:raise Rejected('ekey_terminal_not_last_page')
   q+=25;terminal=True
  if not rows or any(data[q:]):raise Rejected('ekey_page_padding')
  pages.append({'kind':'ekey','index':i,'terminal_sentinel':terminal,'bytes':len(data),'records':rows,'first_key':first.hex(),'md5':digest.hex(),'verified':True})
 footer=b[p:]
 # Observed trailing ESpec for this EN object. It is retained, not executed/interpreted.
 if len(footer)>4096 or not footer or not re.fullmatch(rb'[A-Za-z0-9:*{},=._+\-]+',footer):raise Rejected('unrecognized_footer')
 footer_text=footer.decode('ascii')
 if not footer_text.startswith('b:'):raise Rejected('unrecognized_footer')
 missing=sorted({ek for row in mappings for ek in row['ekeys']}-{ek.hex() for ek in seenek})
 if missing:raise Rejected('ckey_references_missing_ekey')
 return {'signature':'EN','version':version,'input_sha256':hashlib.sha256(b).hexdigest(),'ckey_page_count':ncp,'ekey_page_count':nep,'pages':pages,'espec_strings':especs,'footer':{'bytes':len(footer),'text':footer_text,'sha256':hashlib.sha256(footer).hexdigest(),'semantics_interpreted':False},'ckey_mappings':mappings,'ekey_specs':specs,'runtime_approved':False}
