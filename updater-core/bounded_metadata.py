"""Read exactly a pre-approved metadata budget; no network calls or extra EOF read.
Missing Content-Length is allowed: pin size and verify the format/checksums later.
This does not claim physical wire-byte accounting or unread response length.
"""
from release_core import need
import http.client

def metadata_headers(response,url,size):
 h=response.headers;length=h.get('Content-Length')
 obs={'status':response.status,'final_url':response.geturl(),'content_length':length,'content_range':h.get('Content-Range'),'content_encoding':h.get('Content-Encoding','identity'),'transfer_encoding':h.get('Transfer-Encoding'),'etag':h.get('ETag')}
 need(type(size)is int and 0<size<=4*1024**2,'metadata_budget_type')
 need(response.status==200 and response.geturl()==url and not h.get('Content-Range')and h.get('Content-Encoding','identity').lower()in ('','identity'),'metadata_response_rejected_before_body')
 need(length is None or length==str(size),'metadata_length_rejected_before_body')
 return obs

def read_metadata(response,size,on_bytes):
 parts=[];remaining=size
 while remaining:
  try:b=response.read(min(65536,remaining))
  except http.client.IncompleteRead as e:
   on_bytes(len(e.partial));raise
  need(type(b)is bytes and 0<len(b)<=remaining,'metadata_truncated');on_bytes(len(b));parts.append(b);remaining-=len(b)
 return b''.join(parts)

def capped_metadata_headers(response,url,cap):
 """Size supplied by an old config is a READ CEILING, not a content identity.
 Accept shorter framed response; full index name/footer/TOC/pages must still verify.
 Larger responses are rejected without reading; no budget is expanded.
 """
 length=response.headers.get('Content-Length')
 need(type(cap)is int and 0<cap<=4*1024**2,'metadata_cap_type')
 need(type(length)is str and length.isdecimal() and 28<int(length)<=cap,'metadata_framing_outside_approved_cap')
 size=int(length);return metadata_headers(response,url,size),size

def pinned_index_headers(response,url,per_index_ceiling,remaining_total):
 """Use explicit approved ceilings, NOT positional config size hints as identity.
 Content identity still requires pinned footer name + footer/TOC/all-page hashes.
 This pure helper grants no permission and issues no requests.
 """
 need(type(per_index_ceiling)is int and 28<per_index_ceiling<=4*1024**2 and type(remaining_total)is int and remaining_total>0,'index_read_ceiling_types')
 obs,size=capped_metadata_headers(response,url,min(per_index_ceiling,remaining_total));return obs,size
