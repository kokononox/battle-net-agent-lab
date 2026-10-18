"""Generic bounded Range resume + serialized checkpoint, no implicit network/I/O.
Only supplied small N/Z BLTE objects. Not a complete production downloader,
filesystem journal, Windows installer, publisher authentication or required set.
"""
from dataclasses import dataclass
import base64,hashlib,json,re,urllib.request
from release_core import need,RunCheckpoint,NoRedirect
from local_candidates import ObjectSpec
from local_blte import verify_blte

def identity(checkpoint,spec):
 need(type(checkpoint)is RunCheckpoint and type(spec)is ObjectSpec,'transfer_types')
 return hashlib.sha256(checkpoint.serialize()+json.dumps(spec.public(),sort_keys=True).encode()).hexdigest()
def object_url(checkpoint,spec):
 identity(checkpoint,spec);e=spec.ekey;return checkpoint.target.origins[0]+'/tpr/wow/data/'+e[:2]+'/'+e[2:4]+'/'+e

def strong_etag(tag):return type(tag)is str and re.fullmatch(r'"[!#-~]{1,250}"',tag) is not None
@dataclass(frozen=True)
class RangeResult:
 url:str
 start:int
 end:int
 total:int
 etag:str
 body:bytes
@dataclass(frozen=True)
class ObjectTransfer:
 checkpoint:RunCheckpoint
 spec:ObjectSpec
 partial:bytes=b''
 etag:object=None
 def __post_init__(self):
  identity(self.checkpoint,self.spec);need(type(self.partial)is bytes and len(self.partial)<=self.spec.encoded_size,'partial_bounds');need((not self.partial and self.etag is None) or (bool(self.partial) and strong_etag(self.etag)),'partial_etag')
 def next_range(self,limit):
  need(type(limit)is int and 0<limit<=4*1024**2,'range_chunk_limit');need(len(self.partial)<self.spec.encoded_size,'object_already_complete');return len(self.partial),min(len(self.partial)+limit,self.spec.encoded_size)-1
 def accept(self,result,requested):
  need(type(result)is RangeResult and type(requested)is tuple and len(requested)==2,'range_result_type');a,b=requested;need(type(a)is int and type(b)is int and a==len(self.partial) and a<=b<self.spec.encoded_size,'range_request_geometry')
  need(all(type(v)is int for v in (result.start,result.end,result.total)),'range_result_integer_types');need(result.url==object_url(self.checkpoint,self.spec) and result.start==a and result.end==b and result.total==self.spec.encoded_size and type(result.body)is bytes and len(result.body)==b-a+1,'range_response_geometry');need(strong_etag(result.etag) and (self.etag is None or self.etag==result.etag),'range_entity_changed');return ObjectTransfer(self.checkpoint,self.spec,self.partial+result.body,result.etag)
 def serialize(self):
  d={'format':'bounded-object-resume-1','identity':identity(self.checkpoint,self.spec),'partial_base64':base64.b64encode(self.partial).decode(),'partial_sha256':hashlib.sha256(self.partial).hexdigest(),'etag':self.etag};return json.dumps(d,sort_keys=True,separators=(',',':')).encode()
 @classmethod
 def restore(cls,raw,checkpoint,spec,current_baseline):
  checkpoint.resume(current_baseline);need(type(raw)is bytes and 0<len(raw)<=6*1024**2,'resume_state_budget')
  def pairs(items):
   d={}
   for k,v in items:need(k not in d,'resume_duplicate_field');d[k]=v
   return d
  try:d=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'resume_nonfinite'))
  except (UnicodeError,json.JSONDecodeError):need(False,'resume_json')
  need(type(d)is dict and set(d)=={'format','identity','partial_base64','partial_sha256','etag'} and d['format']=='bounded-object-resume-1' and d['identity']==identity(checkpoint,spec),'resume_identity_changed');need(type(d['partial_base64'])is str,'resume_partial_type')
  try:partial=base64.b64decode(d['partial_base64'],validate=True)
  except (ValueError,TypeError):need(False,'resume_base64')
  need(hashlib.sha256(partial).hexdigest()==d['partial_sha256'],'resume_partial_checksum');return cls(checkpoint,spec,partial,d['etag'])
 def verified(self):
  need(len(self.partial)==self.spec.encoded_size,'object_incomplete');proof=verify_blte(self.partial,self.spec.public());return dict(proof,status='one_pinned_object_verified_in_staging_memory',encoded_sha256=hashlib.sha256(self.partial).hexdigest(),required_set_selected=False,installation_ready=False,apply_authorized=False)

class ApprovedRanges:
 """One exact HTTPS object, explicit ranges and aggregate body-read budget.
 Zero retries/redirects; ignored Range or invalid metadata rejected before body read.
 This is application body-read accounting, not a physical wire-byte guarantee.
 """
 def __init__(self,checkpoint,spec,ranges,approved):
  need(approved is True,'explicit_range_approval_required');self.url=object_url(checkpoint,spec);self.total=spec.encoded_size;need(type(ranges)is tuple and 0<len(ranges)<=64,'approved_range_count');last=-1
  for a,b in ranges:need(type(a)is int and type(b)is int and last<a<=b<self.total,'approved_range_geometry');last=b
  self.allowed=frozenset(ranges);self.attempted=set();self.body_bytes_read=0;self.body_budget=sum(b-a+1 for a,b in ranges)
 def fetch(self,span,expected_etag=None):
  need(span in self.allowed and span not in self.attempted,'range_not_approved_or_repeated');need(expected_etag is None or strong_etag(expected_etag),'invalid_if_range');self.attempted.add(span);a,b=span;n=b-a+1;headers={'User-Agent':'WoW-Updater-Bounded-Resume-Research/0.9','Accept-Encoding':'identity','Range':f'bytes={a}-{b}'}
  if expected_etag is not None:headers['If-Range']=expected_etag
  req=urllib.request.Request(self.url,headers=headers)
  with urllib.request.build_opener(NoRedirect).open(req,timeout=30) as r:
   need(r.status==206 and r.geturl()==self.url and r.headers.get('Content-Range')==f'bytes {a}-{b}/{self.total}' and r.headers.get('Content-Length')==str(n) and r.headers.get('Content-Encoding','identity').lower() in ('','identity'),'range_response_rejected_before_body');tag=r.headers.get('ETag');need(strong_etag(tag) and (expected_etag is None or tag==expected_etag),'range_entity_rejected_before_body');parts=[];remaining=n
   while remaining:
    value=r.read(min(65536,remaining));need(type(value)is bytes and 0<len(value)<=remaining,'range_short_or_invalid_read');remaining-=len(value);self.body_bytes_read+=len(value);need(self.body_bytes_read<=self.body_budget,'range_body_budget');parts.append(value)
  return RangeResult(self.url,a,b,self.total,tag,b''.join(parts))
