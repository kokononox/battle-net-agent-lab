"""Offline HTTP quarantine, no upstream/transport/automatic approval.
POSIX storage is tested; Windows persistence deliberately fails closed.
All values in private records may be sensitive. Never upload private records.
"""
from dataclasses import dataclass,asdict
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from urllib.parse import urlsplit

MAX_REQUEST=32768
MAX_BODY=4096
MAX_RECORDS=16
MAX_STORE_BYTES=1048576
MAX_RECORD_BYTES=262144
HOSTS={'level3.blizzard.com','us.version.battle.net'}
REDACT={'authorization','proxy-authorization','cookie','set-cookie','x-api-key','x-auth-token'}
TOKEN=re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
RECORD_NAME=re.compile(r'[0-9a-f]{32}[.]json')
PUBLIC_REASONS=frozenset({'review_required','request_size_or_type','http_incomplete_or_unsupported','http_request_rejected','http_target_rejected','http_header_rejected','http_host_rejected','http_transfer_encoding_rejected','http_body_rejected','private_directory_permissions','private_file_permissions','private_store_unexpected_entry','private_store_quota','private_store_write_failed','quarantine_unavailable'})

class Rejected(ValueError):pass
def refuse(code):raise Rejected(code)
def sha(b):return hashlib.sha256(b).hexdigest()

@dataclass(frozen=True)
class Receipt:
 schema:str='request_quarantine_receipt_g40_v1'
 decision:str='blocked'
 reason:str='review_required'
 capture_id:str=''
 private_stored:bool=False
 upstream_attempts:int=0
 # No URL, path hash, header value, machine id, time or body digest exported.
 def public(self):return asdict(self)

def parse_http(raw):
 if type(raw) is not bytes or not 0<len(raw)<=MAX_REQUEST:refuse('request_size_or_type')
 if b'\r\n\r\n' not in raw:refuse('http_incomplete_or_unsupported')
 head,body=raw.split(b'\r\n\r\n',1)
 lines=head.decode('iso-8859-1').split('\r\n');request=lines[0].split(' ')
 if len(request)!=3 or request[0] not in {'GET','HEAD','POST'} or request[2] not in {'HTTP/1.0','HTTP/1.1'}:refuse('http_request_rejected')
 method,target,version=request
 if any(ord(c)<33 or ord(c)==127 for c in target):refuse('http_target_rejected')
 headers=[]
 for line in lines[1:]:
  if not line or line[0] in ' \t' or ':' not in line:refuse('http_header_rejected')
  key,value=line.split(':',1)
  if not TOKEN.fullmatch(key) or any(ord(c)<32 and c!='\t' or ord(c)==127 for c in value):refuse('http_header_rejected')
  headers.append((key.lower(),value.strip(' \t')))
 hosts=[v for k,v in headers if k=='host']
 if len(hosts)!=1:refuse('http_host_rejected')
 def authority(text):
  p=text.split(':')
  if len(p)>2 or p[0] not in HOSTS:refuse('http_host_rejected')
  port=80 if len(p)==1 else int(p[1]) if p[1].isdigit() and len(p[1])<=5 else -1
  if port not in {80,1119} or port==1119 and p[0]!='us.version.battle.net':refuse('http_host_rejected')
  return p[0],port
 host,port=authority(hosts[0])
 if target.startswith('/') and not target.startswith('//'):
  u=urlsplit('http://'+hosts[0]+target)
 else:
  u=urlsplit(target)
  if u.scheme!='http' or u.username is not None or u.password is not None or authority(u.netloc)!=(host,port):refuse('http_target_rejected')
 if u.fragment or '#' in target:refuse('http_target_rejected')
 lengths=[v for k,v in headers if k=='content-length']
 if any(k=='transfer-encoding' for k,v in headers):refuse('http_transfer_encoding_rejected')
 if len(lengths)>1 or lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>8):refuse('http_body_rejected')
 length=int(lengths[0]) if lengths else 0
 if length>MAX_BODY or len(body)!=length:refuse('http_body_rejected')
 private_headers=[]
 for key,value in headers:
  item={'name':key,'value':None if key in REDACT else value,'redacted':key in REDACT}
  if key in REDACT:item['value_bytes']=len(value.encode('iso-8859-1'))
  private_headers.append(item)
 return {'schema':'private_http_quarantine_g40_v1','review_status':'pending','approval_granted':False,'method':method,'http_version':version,'host':host,'port':port,'target':target,'path':u.path or '/','query':u.query,'headers':private_headers,'body_bytes':len(body),'body_sha256':sha(body),'body_persisted':False,'raw_request_persisted':False,'captured_before_any_upstream':True}

class PrivateStore:
 """Single trusted-controller POSIX prototype. Not Windows ACL enforcement.
 Directory must already be owner-only. dir_fd anchors file operations.
 Quotas survive reopening via inventory; parallel controllers unsupported.
 """
 def __init__(self,path):
  if os.name!='posix':refuse('windows_storage_not_validated')
  self._fd=None;self._lock=threading.Lock()
  try:
   fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   self._fd=fd;self._check_root();self._inventory()
  except BaseException:
   self.close();raise
 def _check_root(self):
  s=os.fstat(self._fd)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:refuse('private_directory_permissions')
 def _safe_file(self,s):
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:refuse('private_file_permissions')
 def _inventory(self):
  count=0;size=0
  for name in os.listdir(self._fd):
   if not RECORD_NAME.fullmatch(name):refuse('private_store_unexpected_entry')
   s=os.stat(name,dir_fd=self._fd,follow_symlinks=False);self._safe_file(s)
   if s.st_size>MAX_RECORD_BYTES:refuse('private_store_quota')
   count+=1;size+=s.st_size
  if count>MAX_RECORDS or size>MAX_STORE_BYTES:refuse('private_store_quota')
  return count,size
 def write(self,record):
  data=json.dumps(record,ensure_ascii=True,separators=(',',':')).encode('ascii')
  if len(data)>MAX_RECORD_BYTES:refuse('private_store_quota')
  with self._lock:
   self._check_root();count,size=self._inventory()
   if count>=MAX_RECORDS or size+len(data)>MAX_STORE_BYTES:refuse('private_store_quota')
   capture_id=uuid.uuid4().hex;name=capture_id+'.json';fd=None;created=False
   try:
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self._fd);created=True
    self._safe_file(os.fstat(fd))
    view=memoryview(data)
    while view:
     n=os.write(fd,view)
     if n<=0:refuse('private_store_write_failed')
     view=view[n:]
    os.fsync(fd);os.close(fd);fd=None;os.fsync(self._fd)
   except BaseException:
    if fd is not None:os.close(fd)
    if created:os.unlink(name,dir_fd=self._fd)
    raise
   return capture_id
 def read_for_local_review(self,capture_id):
  if type(capture_id) is not str or not re.fullmatch('[0-9a-f]{32}',capture_id):refuse('capture_id_rejected')
  with self._lock:
   self._check_root()
   fd=os.open(capture_id+'.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self._fd)
   try:
    self._safe_file(os.fstat(fd));chunks=[];total=0
    while True:
     chunk=os.read(fd,4096)
     if not chunk:break
     total+=len(chunk)
     if total>MAX_RECORD_BYTES:refuse('private_store_quota')
     chunks.append(chunk)
    return json.loads(b''.join(chunks))
   finally:os.close(fd)
 def close(self):
  if self._fd is not None:os.close(self._fd);self._fd=None
 def __enter__(self):return self
 def __exit__(self,*args):self.close()

class QuarantineGate:
 """No upstream callback exists; every submission remains blocked."""
 def __init__(self,store):
  allowed=(PrivateStore,)
  if os.name=='nt':
   from windows_store import WindowsStore
   allowed=(WindowsStore,)
  if type(store) not in allowed:refuse('private_store_required')
  self._store=store
 def inspect_http(self,raw):
  try:
   record=parse_http(raw);capture_id=self._store.write(record)
   return Receipt(capture_id=capture_id,private_stored=True)
  except Rejected as exc:
   return Receipt(reason=str(exc) if str(exc) in PUBLIC_REASONS else 'quarantine_unavailable')
  except (OSError,ValueError,OverflowError):
   return Receipt(reason='quarantine_unavailable')
