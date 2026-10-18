"""One-pass bounded-memory BLTE verifier for owned input streams, N/Z only.
No network, paths, decoded export or install authority. Numeric caps are parser
budgets, NOT read/download permission. Caller supplies a coherent source.
"""
from dataclasses import dataclass,asdict
import hashlib,struct,zlib
from release_core import need,ck
BLOCK=65536
@dataclass(frozen=True)
class StreamObjectSpec:
 ckey:str
 ekey:str
 decoded_size:int
 encoded_size:int
 def __post_init__(self):
  ck(self.ckey);ck(self.ekey);need(type(self.decoded_size)is int and 0<self.decoded_size<=2**35,'stream_decoded_budget');need(type(self.encoded_size)is int and 9<=self.encoded_size<=2**32,'stream_encoded_budget')
 def public(self):return asdict(self)

def verify_stream(stream,spec):
 need(type(spec)is StreamObjectSpec,'stream_spec_required');encoded=0;decoded=0;em=hashlib.md5();es=hashlib.sha256();cm=hashlib.md5();cs=hashlib.sha256();largest=0
 def exact(n):
  nonlocal encoded,largest
  need(type(n)is int and 0<=n<=12+24*65536 and encoded+n<=spec.encoded_size,'stream_read_budget');parts=[];left=n
  while left:
   request=min(BLOCK,left);raw=stream.read(request);need(type(raw)is bytes and 0<len(raw)<=request,'stream_truncated_or_oversized_read');largest=max(largest,len(raw));left-=len(raw);encoded+=len(raw);em.update(raw);es.update(raw);parts.append(raw)
  return b''.join(parts)
 first=exact(8);need(first[:4]==b'BLTE','stream_blte_magic');hs=int.from_bytes(first[4:],'big')
 if hs:
  need(12<=hs<=12+24*65536 and hs<=spec.encoded_size,'stream_header_budget');header=first+exact(hs-8);need(header[8]==15,'stream_header_flags');count=int.from_bytes(header[9:12],'big');need(0<count<=65536 and hs==12+24*count,'stream_chunk_table');need(hashlib.md5(header).hexdigest()==spec.ekey,'stream_header_ekey')
  rows=[]
  for i in range(count):
   at=12+24*i;size,out=struct.unpack_from('>II',header,at);need(size>0 and out>0,'stream_chunk_geometry');rows.append((size,out,header[at+8:at+24]))
  need(hs+sum(x[0]for x in rows)==spec.encoded_size and sum(x[1]for x in rows)==spec.decoded_size,'stream_declared_totals')
 else:rows=[(spec.encoded_size-8,spec.decoded_size,None)]
 for size,out,wanted in rows:
  chunk=hashlib.md5();mode=exact(1);chunk.update(mode);need(mode in(b'N',b'Z'),'stream_unsupported_mode');z=zlib.decompressobj()if mode==b'Z'else None;left=size-1;written=0
  def emit(raw):
   nonlocal written,decoded
   written+=len(raw);decoded+=len(raw);need(written<=out and decoded<=spec.decoded_size,'stream_decoded_limit');cm.update(raw);cs.update(raw)
  while left:
   raw=exact(min(BLOCK,left));left-=len(raw);chunk.update(raw)
   if z is None:emit(raw)
   else:
    pending=raw
    while pending:
     value=z.decompress(pending,min(BLOCK,out-written+1));emit(value);tail=z.unconsumed_tail;need(not z.unused_data,'stream_zlib_trailing');need(not tail or value or len(tail)<len(pending),'stream_zlib_no_progress');pending=tail
  if z is not None:
   while True:
    value=z.decompress(b'',min(BLOCK,out-written+1));emit(value)
    if not value:break
   need(z.eof and not z.unused_data and not z.unconsumed_tail,'stream_zlib_incomplete')
  need(written==out,'stream_chunk_decoded_size');need(wanted is None or chunk.digest()==wanted,'stream_chunk_checksum')
 need(encoded==spec.encoded_size and decoded==spec.decoded_size,'stream_final_totals')
 if not hs:need(em.hexdigest()==spec.ekey,'stream_headerless_ekey')
 # One extra sentinel read is allowed only on caller-owned streams, never a CDN
 # body/read-scope budget. Segment readers return EOF without touching other files.
 extra=stream.read(1);need(type(extra)is bytes and extra==b'','stream_trailing_bytes')
 need(cm.hexdigest()==spec.ckey,'stream_content_ckey')
 return {'format':'streaming-blte-proof-1','full_ekey_verified':True,'full_ckey_verified':True,'blte_chunk_checksums_verified':bool(hs),'chunk_checksum_scope':'all_table_chunks'if hs else'not_present_headerless','encoded_bytes':encoded,'decoded_bytes':decoded,'encoded_sha256':es.hexdigest(),'decoded_sha256':cs.hexdigest(),'blte_chunks':len(rows),'maximum_source_block_bytes':largest,'header_bytes':hs if hs else 8,'decoded_content_exported':False,'installation_ready':False,'apply_authorized':False}
