"""In-memory, read-only Encoding page parser. No decoder, file opens or writer.
Adapted from the checksum-verified v0.18 parser; all metadata is CKey-checked by caller.
"""
import hashlib
class EncodingError(Exception):pass
class EncodingTable:
 def __init__(self,data):
  self.map=data;d=data
  try:
   if len(d)<22 or d[:5]!=b'EN\x01\x10\x10' or d[17]!=0:raise EncodingError('Unsupported Encoding table header')
   self.cps=int.from_bytes(d[5:7],'big')*1024;self.eps=int.from_bytes(d[7:9],'big')*1024
   self.cn=int.from_bytes(d[9:13],'big');self.en=int.from_bytes(d[13:17],'big');espec=int.from_bytes(d[18:22],'big')
   if not 1024<=self.cps<=65536 or not 1024<=self.eps<=65536 or self.cn>500000 or self.en>500000:raise EncodingError('Unsupported Encoding table bounds')
   self.cindex=22+espec;self.cpages=self.cindex+32*self.cn;self.eindex=self.cpages+self.cps*self.cn;self.epages=self.eindex+32*self.en
   if self.epages+self.eps*self.en>len(d):raise EncodingError('Truncated Encoding page tables')
  except Exception:self.close();raise
 def close(self):pass
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
 def c_records(self,cancel,notify):
  d=self.map;last=None
  for i in range(self.cn):
   if cancel.is_set():raise EncodingError('Cancelled')
   start=self.cpages+i*self.cps;page=d[start:start+self.cps];index=d[self.cindex+32*i:self.cindex+32*i+32]
   if hashlib.md5(page).digest()!=index[16:]:raise EncodingError('CKey page checksum mismatch')
   pos=0;first=True
   while pos<len(page):
    count=page[pos]
    if count==0:
     if any(page[pos:]):raise EncodingError('Unexpected CKey page padding')
     break
    end=pos+22+16*count
    if end>len(page):raise EncodingError('CKey record crosses page boundary')
    size=int.from_bytes(page[pos+1:pos+6],'big');ck=page[pos+6:pos+22]
    if first and ck!=index[:16]:raise EncodingError('CKey page index mismatch')
    if last is not None and ck<=last:raise EncodingError('CKeys are not strictly ordered')
    first=False;last=ck
    yield ck,size,[page[at:at+16] for at in range(pos+22,end,16)]
    pos=end
   if i%500==0:notify('Reading CKey pages '+str(i+1)+' / '+str(self.cn))
 def e_sizes(self,wanted,cancel,notify):
  found={};d=self.map;last=None
  for i in range(self.en):
   if cancel.is_set():raise EncodingError('Cancelled')
   start=self.epages+i*self.eps;page=d[start:start+self.eps];index=d[self.eindex+32*i:self.eindex+32*i+32];first=True
   if hashlib.md5(page).digest()!=index[16:]:raise EncodingError('EKey page checksum mismatch')
   consumed=0
   for pos in range(0,len(page)-24,25):
    ek=page[pos:pos+16]
    if ek==b'\0'*16:
     # Verified official tables use a zero EKey, ESpec index -1 and size 0
     # as an end marker. Accept only that marker or wholly zero padding.
     if page[pos+16:pos+20] not in (b'\0'*4,b'\xff'*4) or any(page[pos+20:]):
      raise EncodingError('Unexpected EKey page terminator')
     consumed=len(page)
     break
    if first and ek!=index[:16]:raise EncodingError('EKey page index mismatch')
    if last is not None and ek<=last:raise EncodingError('EKeys are not strictly ordered')
    last=ek
    first=False
    if ek in wanted:found[ek]=int.from_bytes(page[pos+20:pos+25],'big')
    consumed=pos+25
   if any(page[consumed:]):raise EncodingError('Unexpected EKey page trailing bytes')
   if i%500==0:notify('Reading EKey pages '+str(i+1)+' / '+str(self.en))
  return found
