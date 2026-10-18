"""Owned POSIX staged archive-object prototype, 1 MiB immutable segments.
Restore checks journal/geometry, NOT payload health. verify() freshly checks every
segment and full BLTE content using bounded reads. No network/live game access.
Cooperative single-writer only, not hostile-process/Windows/power-loss qualified.
Old 4 MiB approvals/classes are not widened. Abandoned locks are never broken.
"""
import contextlib,hashlib,json,os,re,stat,uuid
from pathlib import Path
from release_core import need,RunCheckpoint
from archive_transfer import ArchiveSource,ArchiveResponse,archive_url
from cdn_routes import locate_in_verified_archive
from range_resume import strong_etag
from segment_stage import _read,_write_new,_json
from stream_blte import StreamObjectSpec,verify_stream
SEGMENT=1024**2
MAX_SEGMENTS=4096

def stage_identity(cp,spec,source):
 need(type(cp)is RunCheckpoint and type(spec)is StreamObjectSpec and type(source)is ArchiveSource,'stream_stage_types');need(source.offset+spec.encoded_size<=2**32,'stream_stage_archive_span')
 return hashlib.sha256(cp.serialize()+json.dumps({'spec':spec.public(),'source':source.public()},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def bind_stream_source(cp,spec,index,request):
 need(type(spec)is StreamObjectSpec,'stream_spec_required');route=locate_in_verified_archive(index,request,spec.ekey,spec.encoded_size);need(route is not None,'stream_no_full_key_route');source=ArchiveSource(route['archive_key'],route['index_sha256'],route['archive_offset']);stage_identity(cp,spec,source);need(archive_url(cp,source)==route['archive_url'],'stream_route_origin');return source

class _Segments:
 def __init__(self,stage):self.stage=stage;self.rows=stage.doc['segments'];self.at=0;self.file=None;self.left=0;self.hash=None
 def _open(self):
  row=self.rows[self.at];p=self.stage.path/row['name'];fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);self.file=os.fdopen(fd,'rb');s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==row['size'],'stream_segment_type_or_size');self.left=s.st_size;self.hash=hashlib.sha256()
 def read(self,n):
  need(type(n)is int and 0<n<=65536,'stream_segment_read_budget');parts=[];left=n
  while left and self.at<len(self.rows):
   if self.file is None:self._open()
   raw=self.file.read(min(left,self.left));need(type(raw)is bytes and bool(raw),'stream_segment_truncated');self.hash.update(raw);self.left-=len(raw);left-=len(raw);parts.append(raw)
   if not self.left:
    need(self.hash.hexdigest()==self.rows[self.at]['sha256'],'stream_segment_checksum');self.file.close();self.file=None;self.at+=1
  return b''.join(parts)
 def close(self):
  if self.file is not None:self.file.close();self.file=None

class StreamStage:
 @staticmethod
 def _sync(path):
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 @classmethod
 def create(cls,path,cp,spec,source):
  need(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'stream_stage_posix_only');identity=stage_identity(cp,spec,source);p=Path(path);p.mkdir(mode=0o700,exist_ok=False);doc={'format':'stream-segment-stage-1','identity':identity,'committed_bytes':0,'etag':None,'archive_total':None,'segments':[]};_write_new(p/'journal.json',cls._encode(doc));cls._sync(p);return cls.restore(p,cp,spec,source,cp.baseline)
 @staticmethod
 def _encode(doc):return json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
 @classmethod
 def restore(cls,path,cp,spec,source,current_baseline):
  need(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'stream_stage_posix_only');cp.resume(current_baseline);s=cls();s.path=Path(path);st=s.path.lstat();need(stat.S_ISDIR(st.st_mode),'stream_stage_directory');s.inode=(st.st_dev,st.st_ino);s.cp=cp;s.spec=spec;s.source=source;s.identity=stage_identity(cp,spec,source);s._load();return s
 def _root(self):
  s=self.path.lstat();need(stat.S_ISDIR(s.st_mode)and(s.st_dev,s.st_ino)==self.inode,'stream_stage_directory_changed')
 def _load(self):
  self._root();raw=_read(self.path/'journal.json',1024**2);d=_json(raw);need(type(d)is dict and set(d)=={'format','identity','committed_bytes','etag','archive_total','segments'}and d['format']=='stream-segment-stage-1'and d['identity']==self.identity,'stream_stage_identity');need(type(d['committed_bytes'])is int and 0<=d['committed_bytes']<=self.spec.encoded_size and type(d['segments'])is list and len(d['segments'])<=MAX_SEGMENTS,'stream_stage_journal_budget');pos=0;names=set()
  for row in d['segments']:
   need(type(row)is dict and set(row)=={'name','start','size','sha256'},'stream_stage_segment_shape');name=row['name'];need(type(name)is str and re.fullmatch('[a-f0-9]{32}\\.seg',name)is not None and name not in names,'stream_stage_segment_name');names.add(name);need(type(row['start'])is int and row['start']==pos and type(row['size'])is int and 0<row['size']<=SEGMENT and pos+row['size']<=self.spec.encoded_size,'stream_stage_geometry');need(type(row['sha256'])is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])is not None,'stream_stage_digest_shape');pos+=row['size']
  need(pos==d['committed_bytes'],'stream_stage_committed_geometry')
  if pos:need(strong_etag(d['etag'])and type(d['archive_total'])is int and self.source.offset+self.spec.encoded_size<=d['archive_total']<=2**63-1,'stream_stage_entity')
  else:need(d['etag']is None and d['archive_total']is None,'stream_stage_empty_entity')
  self.doc=d;self.journal_sha=hashlib.sha256(raw).hexdigest()
 @contextlib.contextmanager
 def _lock(self):
  self._root();p=self.path/'writer.lock';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:yield
  finally:os.close(fd);p.unlink()
 def next_range(self):
  self._load();n=self.doc['committed_bytes'];need(n<self.spec.encoded_size and len(self.doc['segments'])<MAX_SEGMENTS,'stream_stage_complete_or_segment_budget');return n,min(n+SEGMENT,self.spec.encoded_size)-1
 def append(self,response,relative,*,_fault=None):
  with self._lock():
   before=self.journal_sha;self._load();need(self.journal_sha==before,'stream_stage_stale_writer');need(type(response)is ArchiveResponse and type(relative)is tuple and len(relative)==2,'stream_stage_response_type');a,b=relative;need(type(a)is int and type(b)is int and a==self.doc['committed_bytes']and a<=b<self.spec.encoded_size and b-a+1<=SEGMENT and len(self.doc['segments'])<MAX_SEGMENTS,'stream_stage_append_geometry');need(all(type(v)is int for v in(response.start,response.end,response.total))and response.url==archive_url(self.cp,self.source)and(response.start,response.end)==(self.source.offset+a,self.source.offset+b)and self.source.offset+self.spec.encoded_size<=response.total<=2**63-1 and type(response.body)is bytes and len(response.body)==b-a+1,'stream_stage_response_geometry');need(strong_etag(response.etag)and(self.doc['etag']is None or self.doc['etag']==response.etag)and(self.doc['archive_total']is None or self.doc['archive_total']==response.total),'stream_stage_entity_changed')
   name=uuid.uuid4().hex+'.seg';_write_new(self.path/name,response.body);self._sync(self.path)
   if _fault:_fault('segment_synced')
   d=dict(self.doc);d.update(committed_bytes=b+1,etag=response.etag,archive_total=response.total,segments=self.doc['segments']+[{'name':name,'start':a,'size':b-a+1,'sha256':hashlib.sha256(response.body).hexdigest()}]);raw=self._encode(d);need(len(raw)<=1024**2,'stream_stage_journal_overflow');tmp=self.path/(uuid.uuid4().hex+'.tmp');_write_new(tmp,raw)
   if _fault:_fault('journal_synced')
   os.replace(tmp,self.path/'journal.json');self._sync(self.path)
   if _fault:_fault('journal_replaced')
   self._load()
  return self.summary()
 def summary(self):return {'format':'stream-segment-stage-summary-1','committed_bytes':self.doc['committed_bytes'],'segments':len(self.doc['segments']),'payload_reverified':False,'network_requests':0,'installation_ready':False,'apply_authorized':False}
 def verify(self):
  with self._lock():
   self._load();need(self.doc['committed_bytes']==self.spec.encoded_size,'stream_stage_incomplete');reader=_Segments(self)
   try:proof=verify_stream(reader,self.spec)
   finally:reader.close()
   return dict(proof,all_segment_sha256_reverified=True,active_generation_proven=False,source=self.source.public(),target=self.cp.target.public(),network_requests=0,game_access=False)
