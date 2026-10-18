"""Exact granted archive ranges, no retries/redirects/decompression/EOF probe.
Only a new explicit transfer grant enables this adapter. Import does no network.
Caller/controller must persist an attempt before fetch. Budgets count application
body reads/reservations, not TCP/TLS wire traffic. No game installation or scan.
"""
import http.client,re,urllib.request,urllib.error
from release_core import need,NoRedirect
from range_resume import strong_etag
from archive_transfer import ArchiveResponse,archive_url
from transfer_controller import TransferGrant,RangeRequest
class ApprovedStreamHTTP:
 def __init__(self,stages,grant,*,approved_network,opener=None):
  need(approved_network is True and type(grant)is TransferGrant,'stream_http_new_explicit_approval_required');grant.match(stages);self.grant=grant;self.allowed={};self.attempted=set();self.body_bytes_read=0
  for i,a,b in grant.ranges:
   s=stages[i];self.allowed[(grant.identities[i],(a,b))]=(archive_url(s.cp,s.source),s.source.offset+a,s.source.offset+b,s.source.offset+s.spec.encoded_size)
  self.open=opener if opener is not None else urllib.request.build_opener(NoRedirect).open;need(callable(self.open),'stream_http_opener')
 @staticmethod
 def header(headers,name,*,required=True):
  values=(headers.get_all(name)or[])if hasattr(headers,'get_all')else([headers[name]]if name in headers else[])
  need(len(values)==1 if required else len(values)<=1,'stream_http_ambiguous_header');need(all(type(v)is str for v in values),'stream_http_header_type');return values[0]if values else None
 def fetch(self,req):
  need(type(req)is RangeRequest,'stream_http_request_type');key=(req.stage_identity,req.relative);need(key in self.allowed and key not in self.attempted,'stream_http_range_not_granted_or_repeated');url,a,b,minimum=self.allowed[key];need((req.url,req.start,req.end)==(url,a,b),'stream_http_request_binding');need(req.expected_etag is None or strong_etag(req.expected_etag),'stream_http_if_range');need(req.expected_total is None or type(req.expected_total)is int and minimum<=req.expected_total<=2**63-1,'stream_http_total_type');n=b-a+1
  need(len(self.attempted)<self.grant.max_requests and self.body_bytes_read+n<=self.grant.max_body_bytes,'stream_http_budget');self.attempted.add(key);headers={'User-Agent':'WoW-Updater-Explicit-Stream/0.20','Accept-Encoding':'identity','Range':f'bytes={a}-{b}'}
  if req.expected_etag is not None:headers['If-Range']=req.expected_etag
  request=urllib.request.Request(url,headers=headers)
  try:response=self.open(request,timeout=30)
  except urllib.error.HTTPError as error:error.close();raise
  with response as r:
   need(r.status==206 and r.geturl()==url,'stream_http_status_or_redirect');h=r.headers;need(self.header(h,'Transfer-Encoding',required=False)is None,'stream_http_transfer_encoding');length=self.header(h,'Content-Length');encoding=self.header(h,'Content-Encoding',required=False);content_range=self.header(h,'Content-Range');etag=self.header(h,'ETag');need(length==str(n)and(encoding is None or encoding.lower()in('','identity')),'stream_http_length_or_encoding');m=re.fullmatch(r'bytes ([0-9]{1,20})-([0-9]{1,20})/([0-9]{1,20})',content_range);need(m is not None,'stream_http_content_range');x,y,total=map(int,m.groups());need((x,y)==(a,b)and minimum<=total<=2**63-1 and(req.expected_total is None or req.expected_total==total),'stream_http_range_entity');need(strong_etag(etag)and(req.expected_etag is None or req.expected_etag==etag),'stream_http_etag_changed');parts=[];left=n
   while left:
    limit=min(65536,left)
    try:value=r.read(limit)
    except http.client.IncompleteRead as error:
     need(type(error.partial)is bytes,'stream_http_partial_type');self.body_bytes_read+=len(error.partial);raise
    need(type(value)is bytes,'stream_http_body_type');self.body_bytes_read+=len(value);need(0<len(value)<=limit and self.body_bytes_read<=self.grant.max_body_bytes,'stream_http_body_budget_or_truncation');parts.append(value);left-=len(value)
  return ArchiveResponse(url,a,b,total,etag,b''.join(parts))
