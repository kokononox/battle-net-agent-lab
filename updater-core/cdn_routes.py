"""Pure bounded archive-index plan pinned to target + CDN config; no I/O.
An EKey absent from loose index is not by itself proof of an archive location.
"""
from dataclasses import dataclass,asdict
import re
from config_binding import config
from release_core import need,ck,TargetSnapshot
from cdn_index import CdnIndex
@dataclass(frozen=True)
class IndexRequest:
 archive_key:str
 url:str
 expected_size:int
 def public(self):return asdict(self)
def archive_index_plan(target,raw_config):
 need(type(target)is TargetSnapshot,'routing_target_type');d=config(raw_config,target.cdn_config);keys=d.get('archives',[]);sizes=d.get('archives-index-size',[]);need(0<len(keys)<=4096 and len(keys)==len(sizes) and len(set(keys))==len(keys),'archive_list_geometry');out=[]
 for k,s in zip(keys,sizes):
  ck(k);need(re.fullmatch('[0-9]{1,9}',s)is not None and 28<int(s)<=4*1024**2,'archive_index_size');out.append(IndexRequest(k,target.origins[0]+'/tpr/wow/data/'+k[:2]+'/'+k[2:4]+'/'+k+'.index',int(s)))
 return tuple(out)
def locate_in_verified_archive(index,request,ekey,encoded_size):
 need(type(index)is CdnIndex and type(request)is IndexRequest and index.index_key==request.archive_key and index.route_kind=='archive','archive_route_identity')
 matches=index.lookup(ekey,encoded_size);need(len(matches)<=1,'ambiguous_archive_route_requires_review')
 if not matches:return None
 row=matches[0];need(type(row.offset)is int and 0<=row.offset<2**32 and row.offset+encoded_size<=2**32,'archive_span_bounds')
 return {'archive_key':request.archive_key,'archive_url':request.url[:-6],'index_sha256':index.sha256,'ekey':ekey,'encoded_size':encoded_size,'archive_offset':row.offset,'end_inclusive':row.offset+encoded_size-1,'source':'verified_full_key_index_record','payload_identity_verified':False,'physical_archive_total_size_known':False,'installation_ready':False,'apply_authorized':False}
