"""G36 offline request-construction prototype. No sockets, TLS or Windows mutation.
A reviewed catalog is trusted input, never client-supplied policy. Hash pinning
binds bytes; it cannot establish that a resource/reviewer is privacy-safe.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

HOSTS=frozenset({'level3.blizzard.com','us.version.battle.net'})
SCHEMA='offline_download_catalog_v1'
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

class Catalog:
 def __init__(self,resources,policy_sha256):
  self.resources=MappingProxyType(dict(resources))
  self.policy_sha256=policy_sha256
 @classmethod
 def load(cls,raw,trusted_digest):
  # trusted_digest must come from trusted deployment, NOT the request caller.
  if type(raw) is not bytes or len(raw)>MAX_POLICY or not hash_string(trusted_digest) or digest(raw)!=trusted_digest:reject('policy_pin_mismatch')
  policy=parse(raw,MAX_POLICY)
  exact_keys(policy,{'schema','resources'},'policy_shape')
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
  return cls(resources,trusted_digest)
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

class OfflineBroker:
 def __init__(self,catalog,transport):
  if type(catalog) is not Catalog or type(transport) is not InMemoryTransport:reject('offline_transport_required')
  self.catalog=catalog;self.transport=transport
 def download(self,raw_request):
  plan=self.catalog.plan(raw_request) # reject unknown input before fetch
  reply=self.transport.fetch(plan)
  if type(reply) is not Reply or type(reply.status) is not int or reply.status!=200:reject('response_status_rejected')
  if type(reply.body) is not bytes or len(reply.body)!=plan.expected_bytes:reject('response_size_rejected')
  if digest(reply.body)!=plan.sha256:reject('response_hash_rejected')
  return reply.body
