"""Bounded small-object Range resume from a VERIFIED CDN archive location.
No whole archive reads. No network on import. No game I/O or installation.
Source location, target/baseline, ETag and archive total are pinned on restore.
The in-JSON partial checkpoint is a research prototype, not a large-file journal.
"""
from dataclasses import dataclass,asdict
import base64,hashlib,json,re,urllib.request,urllib.error,http.client
from release_core import RunCheckpoint,need,ck,sha,NoRedirect
from local_candidates import ObjectSpec
from local_blte import verify_blte
from range_resume import strong_etag
from cdn_routes import locate_in_verified_archive

@dataclass(frozen=True)
class ArchiveSource:
 archive_key:str
 index_sha256:str
 offset:int
 def __post_init__(self):
  ck(self.archive_key);sha(self.index_sha256);need(type(self.offset)is int and 0<=self.offset<2**32,'archive_source_offset')
 def public(self):return asdict(self)

def bind_source(checkpoint,spec,index,request):
 need(type(checkpoint)is RunCheckpoint and type(spec)is ObjectSpec,'archive_binding_types')
 route=locate_in_verified_archive(index,request,spec.ekey,spec.encoded_size);need(route is not None,'no_full_key_size_archive_route')
 source=ArchiveSource(route['archive_key'],route['index_sha256'],route['archive_offset']);need(archive_url(checkpoint,source)==route['archive_url'],'archive_origin_changed');return source

def archive_url(checkpoint,source):
 need(type(checkpoint)is RunCheckpoint and type(source)is ArchiveSource,'archive_url_types');k=source.archive_key;return checkpoint.target.origins[0]+'/tpr/wow/data/'+k[:2]+'/'+k[2:4]+'/'+k

def identity(checkpoint,spec,source):
 need(type(checkpoint)is RunCheckpoint and type(spec)is ObjectSpec and type(source)is ArchiveSource,'archive_transfer_types');need(source.offset+spec.encoded_size<=2**32,'archive_source_span')
 return hashlib.sha256(checkpoint.serialize()+json.dumps({'spec':spec.public(),'source':source.public()},sort_keys=True,separators=(',',':')).encode()).hexdigest()

@dataclass(frozen=True)
class ArchiveResponse:
 url:str
 start:int
 end:int
 total:int
 etag:str
 body:bytes

@dataclass(frozen=True)
class ArchiveTransfer:
 checkpoint:RunCheckpoint
 spec:ObjectSpec
 source:ArchiveSource
 partial:bytes=b''
 etag:object=None
 archive_total:object=None
 def __post_init__(self):
  identity(self.checkpoint,self.spec,self.source);need(type(self.partial)is bytes and len(self.partial)<=self.spec.encoded_size,'archive_partial_bounds')
  if not self.partial:need(self.etag is None and self.archive_total is None,'archive_empty_partial_state')
  else:need(strong_etag(self.etag) and type(self.archive_total)is int and self.source.offset+self.spec.encoded_size<=self.archive_total<=2**63-1,'archive_partial_entity_state')
 def accept(self,result,relative):
  need(type(result)is ArchiveResponse and type(relative)is tuple and len(relative)==2,'archive_response_type');a,b=relative;need(type(a)is int and type(b)is int and a==len(self.partial) and a<=b<self.spec.encoded_size,'archive_relative_geometry')
  need(all(type(v)is int for v in (result.start,result.end,result.total)) and result.url==archive_url(self.checkpoint,self.source) and result.start==self.source.offset+a and result.end==self.source.offset+b and self.source.offset+self.spec.encoded_size<=result.total<=2**63-1 and type(result.body)is bytes and len(result.body)==b-a+1,'archive_physical_geometry')
  need(strong_etag(result.etag) and(self.etag is None or self.etag==result.etag) and(self.archive_total is None or self.archive_total==result.total),'archive_entity_changed')
  return ArchiveTransfer(self.checkpoint,self.spec,self.source,self.partial+result.body,result.etag,result.total)
 def serialize(self):
  return json.dumps({'format':'bounded-archive-resume-1','identity':identity(self.checkpoint,self.spec,self.source),'partial_base64':base64.b64encode(self.partial).decode(),'partial_sha256':hashlib.sha256(self.partial).hexdigest(),'etag':self.etag,'archive_total':self.archive_total},sort_keys=True,separators=(',',':')).encode()
 @classmethod
 def restore(cls,raw,checkpoint,spec,source,current_baseline):
  checkpoint.resume(current_baseline);need(type(raw)is bytes and 0<len(raw)<=6*1024**2,'archive_checkpoint_budget')
  def pairs(items):
   d={}
   for k,v in items:need(k not in d,'archive_checkpoint_duplicate');d[k]=v
   return d
  try:d=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'archive_checkpoint_nonfinite'))
  except (UnicodeError,json.JSONDecodeError):need(False,'archive_checkpoint_json')
  need(type(d)is dict and set(d)=={'format','identity','partial_base64','partial_sha256','etag','archive_total'} and d['format']=='bounded-archive-resume-1' and d['identity']==identity(checkpoint,spec,source),'archive_checkpoint_identity_changed');need(type(d['partial_base64'])is str,'archive_checkpoint_partial_type')
  try:part=base64.b64decode(d['partial_base64'],validate=True)
  except (ValueError,TypeError):need(False,'archive_checkpoint_base64')
  need(hashlib.sha256(part).hexdigest()==d['partial_sha256'],'archive_checkpoint_partial_checksum');return cls(checkpoint,spec,source,part,d['etag'],d['archive_total'])
 def verified(self):
  need(len(self.partial)==self.spec.encoded_size,'archive_object_incomplete');proof=verify_blte(self.partial,self.spec.public());return dict(proof,status='one_archived_object_verified',encoded_sha256=hashlib.sha256(self.partial).hexdigest(),source=self.source.public(),archive_total=self.archive_total,required_set_selected=False,installation_ready=False,apply_authorized=False)

class ApprovedArchiveRanges:
 """Explicit relative ranges only, exact Content-Range, no redirects/retries.
 Application body-read budget, not physical wire-byte guarantee.
 """
 def __init__(self,checkpoint,spec,source,ranges,approved):
  need(approved is True,'explicit_archive_range_approval_required');identity(checkpoint,spec,source);need(type(ranges)is tuple and 0<len(ranges)<=64,'approved_archive_range_count');last=-1
  for a,b in ranges:need(type(a)is int and type(b)is int and last<a<=b<spec.encoded_size,'approved_archive_range_geometry');last=b
  self.url=archive_url(checkpoint,source);self.source=source;self.spec=spec;self.allowed=frozenset(ranges);self.attempted=set();self.body_bytes_read=0;self.body_budget=sum(b-a+1 for a,b in ranges);self.observations=[]
 def fetch(self,relative,expected_etag=None,expected_total=None):
  need(relative in self.allowed and relative not in self.attempted,'archive_range_not_approved_or_repeated');need(expected_etag is None or strong_etag(expected_etag),'archive_if_range_type');need(expected_total is None or type(expected_total)is int,'archive_expected_total_type')
  self.attempted.add(relative);a,b=relative;x,y=self.source.offset+a,self.source.offset+b;n=b-a+1;headers={'User-Agent':'WoW-Updater-Approved-Archive-Resume/0.11','Accept-Encoding':'identity','Range':f'bytes={x}-{y}'}
  if expected_etag is not None:headers['If-Range']=expected_etag
  req=urllib.request.Request(self.url,headers=headers)
  try:r=urllib.request.build_opener(NoRedirect).open(req,timeout=30)
  except urllib.error.HTTPError as e:self.observations.append({'status':e.code,'body_bytes_read':0});e.close();raise
  with r:
   h=r.headers;obs={'status':r.status,'final_url':r.geturl(),'content_range':h.get('Content-Range'),'content_length':h.get('Content-Length'),'content_encoding':h.get('Content-Encoding','identity'),'etag':h.get('ETag')};self.observations.append(obs)
   need(r.status==206 and r.geturl()==self.url and h.get('Content-Length')==str(n) and h.get('Content-Encoding','identity').lower()in ('','identity'),'archive_range_response_rejected_before_body');m=re.fullmatch(r'bytes ([0-9]{1,20})-([0-9]{1,20})/([0-9]{1,20})',h.get('Content-Range',''));need(m is not None,'archive_content_range_syntax');rx,ry,total=map(int,m.groups());need((rx,ry)==(x,y) and self.source.offset+self.spec.encoded_size<=total<=2**63-1 and(expected_total is None or total==expected_total),'archive_content_range_geometry');tag=h.get('ETag');need(strong_etag(tag) and(expected_etag is None or tag==expected_etag),'archive_range_entity_rejected_before_body');parts=[];left=n
   while left:
    try:value=r.read(min(65536,left))
    except http.client.IncompleteRead as e:self.body_bytes_read+=len(e.partial);raise
    need(type(value)is bytes and 0<len(value)<=left,'archive_range_truncated');self.body_bytes_read+=len(value);need(self.body_bytes_read<=self.body_budget,'archive_range_body_budget');parts.append(value);left-=len(value)
  return ArchiveResponse(self.url,x,y,total,tag,b''.join(parts))
