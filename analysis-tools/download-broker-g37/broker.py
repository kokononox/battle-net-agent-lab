"""G37 offline fixed-session request prototype. No sockets, TLS or Windows mutation.
A reviewed catalog is trusted input, never client-supplied policy. Hash pinning
binds bytes; it cannot establish that a resource/reviewer is privacy-safe.
"""
from dataclasses import dataclass
import hashlib
import json
import re
import threading
from types import MappingProxyType

HOSTS=frozenset({'level3.blizzard.com','us.version.battle.net'})
SCHEMA='offline_download_catalog_v2'
MAX_POLICY=65536
MAX_REQUEST=256

class Denied(ValueError):
 def __init__(self,code):
  self.code=code
  super().__init__(code)

def reject(code):raise Denied(code)
def exact_keys(value,keys,code):
 if type(value) is not dict or set(value)!=set(keys):reject(code)
def no_duplicates(pairs):
 value={}
 for key,item in pairs:
  if key in value:reject('duplicate_json_key')
  value[key]=item
 return value

def parse(raw,limit):
 if type(raw) is not bytes or len(raw)>limit:reject('input_size_or_type')
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=no_duplicates,parse_constant=lambda _:reject('nonfinite_json'))
 except Denied:raise
 except (UnicodeError,ValueError,RecursionError):reject('invalid_json')

def digest(value):return hashlib.sha256(value).hexdigest()
def hash_string(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

@dataclass(frozen=True)
class Resource:
 resource_id:str
 host:str
 path:str
 expected_bytes:int
 sha256:str

@dataclass(frozen=True)
class Plan:
 resource_id:str
 host:str
 port:int
 scheme:str
 request:bytes
 expected_bytes:int
 sha256:str

@dataclass(frozen=True)
class SessionSpec:
 resource_ids:tuple
 max_requests:int
 max_total_bytes:int

class Catalog:
 def __init__(self,resources,policy_sha256,session):
  self.resources=MappingProxyType(dict(resources))
  self.policy_sha256=policy_sha256
  self.session=session
 @classmethod
 def load(cls,raw,trusted_digest):
  # trusted_digest must come from trusted deployment, NOT the request caller.
  if type(raw) is not bytes or len(raw)>MAX_POLICY or not hash_string(trusted_digest) or digest(raw)!=trusted_digest:reject('policy_pin_mismatch')
  policy=parse(raw,MAX_POLICY)
  exact_keys(policy,{'schema','resources','session'},'policy_shape')
  if policy['schema']!=SCHEMA or type(policy['resources']) is not list or len(policy['resources'])>64:reject('policy_schema')
  resources={}
  for row in policy['resources']:
   exact_keys(row,{'resource_id','host','path','expected_bytes','sha256','review'},'resource_shape')
   rid=row['resource_id'];host=row['host'];path=row['path'];review=row['review']
   if type(rid) is not str or re.fullmatch('[a-z][a-z0-9_-]{0,31}',rid) is None or rid in resources:reject('resource_id_invalid')
   if type(host) is not str or host not in HOSTS:reject('resource_host_invalid')
   # Strict canonical static path: no query, fragments, escaping or traversal.
   if type(path) is not str or len(path)>512 or re.fullmatch('/[A-Za-z0-9._/-]+',path) is None or '//' in path or any(p in {'.','..',''} for p in path.split('/')[1:]):reject('resource_path_invalid')
   if type(row['expected_bytes']) is not int or not 1<=row['expected_bytes']<=512*1024*1024 or not hash_string(row['sha256']):reject('resource_integrity_invalid')
   exact_keys(review,{'status','evidence_id'},'review_missing')
   if review['status']!='approved' or type(review['evidence_id']) is not str or re.fullmatch('[a-z][a-z0-9_-]{0,63}',review['evidence_id']) is None:reject('review_missing')
   resources[rid]=Resource(rid,host,path,row['expected_bytes'],row['sha256'])
  session=policy['session']
  exact_keys(session,{'resource_ids','max_requests','max_total_bytes'},'session_shape')
  ids=session['resource_ids']
  if type(ids) is not list or len(ids)>64 or any(type(rid) is not str for rid in ids):reject('session_sequence_invalid')
  if len(set(ids))!=len(ids) or set(ids)!=set(resources):reject('session_sequence_invalid')
  if type(session['max_requests']) is not int or session['max_requests']!=len(ids):reject('session_request_budget_invalid')
  total=sum(resources[rid].expected_bytes for rid in ids)
  if type(session['max_total_bytes']) is not int or session['max_total_bytes']!=total or total>512*1024*1024:reject('session_byte_budget_invalid')
  return cls(resources,trusted_digest,SessionSpec(tuple(ids),len(ids),total))
 def plan(self,raw_request):
  request=parse(raw_request,MAX_REQUEST)
  exact_keys(request,{'resource_id'},'request_shape')
  rid=request['resource_id']
  if type(rid) is not str or rid not in self.resources:reject('resource_not_approved')
  resource=self.resources[rid]
  wire=(f'GET {resource.path} HTTP/1.1\r\nHost: {resource.host}\r\n'
        'Accept: application/octet-stream\r\nAccept-Encoding: identity\r\n'
        'User-Agent: BNet-Isolated-Downloader/0.1\r\nConnection: close\r\n\r\n').encode('ascii')
  return Plan(rid,resource.host,443,'https',wire,resource.expected_bytes,resource.sha256)

@dataclass(frozen=True)
class Reply:
 status:int
 body:bytes

class InMemoryTransport:
 """Only fixture lookup. Not an HTTP or TLS transport, cannot follow redirects."""
 def __init__(self,replies):self.replies=dict(replies);self.calls=[]
 def fetch(self,plan):
  self.calls.append(plan)
  key=(plan.host,plan.request)
  if key not in self.replies:reject('fixture_unavailable')
  return self.replies[key]

@dataclass(frozen=True)
class SessionState:
 phase:str
 attempts_reserved:int
 expected_bytes_reserved:int
 verified_bytes_delivered:int
 request_wire_bytes:int

class OfflineBroker:
 """One non-resumable session, fixed order, no retry/reset or client policy API.
 The trusted controller must prevent opening replacement sessions. This class
 is not a sandbox boundary against code executing inside its own process.
 """
 def __init__(self,catalog,transport):
  if type(catalog) is not Catalog or type(transport) is not InMemoryTransport:reject('offline_transport_required')
  self._catalog=catalog;self._transport=transport;self._lock=threading.Lock()
  self._plans=tuple(catalog.plan(json.dumps({'resource_id':rid}).encode()) for rid in catalog.session.resource_ids)
  self._max_wire_bytes=sum(len(p.request) for p in self._plans)
  self._attempts=0;self._reserved=0;self._delivered=0;self._wire=0
  self._phase='active' if self._plans else 'complete'
 def snapshot(self):
  with self._lock:return SessionState(self._phase,self._attempts,self._reserved,self._delivered,self._wire)
 def cancel(self):
  with self._lock:
   if self._phase=='active':self._phase='cancelled'
 def download(self,raw_request):
  with self._lock:
   if self._phase!='active':reject('session_terminal')
   try:
    plan=self._catalog.plan(raw_request)
    if self._attempts>=len(self._plans) or plan!=self._plans[self._attempts]:reject('session_order_rejected')
    if self._attempts+1>self._catalog.session.max_requests or self._reserved+plan.expected_bytes>self._catalog.session.max_total_bytes or self._wire+len(plan.request)>self._max_wire_bytes:reject('session_budget_exhausted')
    # Reserve irreversibly BEFORE fetch. Failed status/size/hash spends this slot.
    self._attempts+=1;self._reserved+=plan.expected_bytes;self._wire+=len(plan.request)
    reply=self._transport.fetch(plan)
    if type(reply) is not Reply or type(reply.status) is not int or reply.status!=200:reject('response_status_rejected')
    if type(reply.body) is not bytes or len(reply.body)!=plan.expected_bytes:reject('response_size_rejected')
    if digest(reply.body)!=plan.sha256:reject('response_hash_rejected')
    self._delivered+=len(reply.body)
    if self._attempts==len(self._plans):self._phase='complete'
    return reply.body
   except BaseException:
    # Includes interruption: no refund, automatic retry or live resume.
    self._phase='failed'
    raise
