"""Offline POSIX prototype: immutable small-object segments + atomic journal.
No network or game I/O. Caller supplies a NEW directory under trusted scratch.
Not a Windows installer, hostile-process defense, or power-loss qualification.
Current BLTE verifier still caps encoded objects at 4 MiB and verifies in RAM.
Uncommitted orphan segments are ignored, never auto-adopted or deleted.
An abandoned exclusive lock is fail-closed, never automatically broken.
"""
import contextlib,hashlib,json,os,re,stat,uuid
from pathlib import Path
from release_core import need
from archive_transfer import identity,archive_url,ArchiveResponse
from range_resume import strong_etag
from local_blte import verify_blte


def _json(raw):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'stage_duplicate_json_key');d[k]=v
  return d
 try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'stage_nonfinite'))
 except (UnicodeError,json.JSONDecodeError):need(False,'stage_invalid_json')


def _read(path,cap):
 flags=os.O_RDONLY|os.O_NOFOLLOW
 fd=os.open(path,flags)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap,'stage_file_type_or_budget')
  raw=f.read(cap+1);need(len(raw)==s.st_size,'stage_file_changed_or_budget');return raw


def _write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())


class SegmentStage:
 """Cooperative single-writer bounded staging. All lengths are relative to object."""
 @classmethod
 def create(cls,path,checkpoint,spec,source):
  need(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'stage_posix_prototype_only')
  identity(checkpoint,spec,source);p=Path(path);p.mkdir(mode=0o700,exist_ok=False)
  doc={'format':'bounded-segment-stage-1','identity':identity(checkpoint,spec,source),'committed_bytes':0,'etag':None,'archive_total':None,'segments':[]}
  _write_new(p/'journal.json',cls._encode(doc));cls._sync(p)
  return cls.restore(p,checkpoint,spec,source,checkpoint.baseline)
 @staticmethod
 def _encode(doc):return json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
 @staticmethod
 def _sync(p):
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 @classmethod
 def restore(cls,path,checkpoint,spec,source,current_baseline):
  need(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'stage_posix_prototype_only');checkpoint.resume(current_baseline)
  obj=cls();obj.path=Path(path);s=obj.path.lstat();need(stat.S_ISDIR(s.st_mode),'stage_directory_required');obj.inode=(s.st_dev,s.st_ino)
  obj.cp=checkpoint;obj.spec=spec;obj.source=source;obj.id=identity(checkpoint,spec,source);obj._load();return obj
 def _root(self):
  s=self.path.lstat();need(stat.S_ISDIR(s.st_mode) and(s.st_dev,s.st_ino)==self.inode,'stage_directory_changed')
 def _load(self):
  self._root();raw=_read(self.path/'journal.json',32768);d=_json(raw)
  need(type(d)is dict and set(d)=={'format','identity','committed_bytes','etag','archive_total','segments'} and d['format']=='bounded-segment-stage-1' and d['identity']==self.id,'stage_identity_changed')
  need(type(d['segments'])is list and len(d['segments'])<=64 and type(d['committed_bytes'])is int and 0<=d['committed_bytes']<=self.spec.encoded_size,'stage_journal_budget')
  pos=0;names=set()
  for seg in d['segments']:
   need(type(seg)is dict and set(seg)=={'name','start','size','sha256'},'stage_segment_shape')
   name=seg['name'];need(type(name)is str and re.fullmatch(r'[a-f0-9]{32}\.seg',name)is not None and name not in names,'stage_segment_name');names.add(name)
   need(type(seg['start'])is int and seg['start']==pos and type(seg['size'])is int and 0<seg['size']<=1024**2 and pos+seg['size']<=self.spec.encoded_size,'stage_segment_geometry')
   data=_read(self.path/name,seg['size']);need(len(data)==seg['size'] and hashlib.sha256(data).hexdigest()==seg['sha256'],'stage_segment_corrupt');pos+=len(data)
  need(pos==d['committed_bytes'],'stage_commit_geometry')
  if pos:need(strong_etag(d['etag']) and type(d['archive_total'])is int and self.source.offset+self.spec.encoded_size<=d['archive_total']<=2**63-1,'stage_entity_state')
  else:need(d['etag']is None and d['archive_total']is None,'stage_empty_entity')
  self.doc=d;self.journal_sha=hashlib.sha256(raw).hexdigest()
 @contextlib.contextmanager
 def _lock(self):
  self._root();p=self.path/'writer.lock';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:yield
  finally:os.close(fd);p.unlink()
 def append(self,response,relative,*,_fault=None):
  """Input is a pre-bounded verified-header transport response; no fetching here.
  _fault is test-only crash simulation, never used by network controllers.
  """
  with self._lock():
   previous=self.journal_sha;self._load();need(self.journal_sha==previous,'stage_stale_writer')
   need(type(response)is ArchiveResponse and type(relative)is tuple and len(relative)==2,'stage_response_type');a,b=relative
   need(type(a)is int and type(b)is int and a==self.doc['committed_bytes'] and a<=b<self.spec.encoded_size and b-a+1<=1024**2 and len(self.doc['segments'])<64,'stage_append_geometry')
   need(all(type(x)is int for x in (response.start,response.end,response.total)) and response.url==archive_url(self.cp,self.source) and(response.start,response.end)==(self.source.offset+a,self.source.offset+b) and self.source.offset+self.spec.encoded_size<=response.total<=2**63-1 and type(response.body)is bytes and len(response.body)==b-a+1,'stage_response_geometry')
   need(strong_etag(response.etag) and(self.doc['etag']is None or response.etag==self.doc['etag']) and(self.doc['archive_total']is None or response.total==self.doc['archive_total']),'stage_entity_changed')
   name=uuid.uuid4().hex+'.seg';_write_new(self.path/name,response.body);self._sync(self.path)
   if _fault:_fault('segment_synced')
   d=dict(self.doc);d.update(committed_bytes=b+1,etag=response.etag,archive_total=response.total,segments=self.doc['segments']+[{'name':name,'start':a,'size':len(response.body),'sha256':hashlib.sha256(response.body).hexdigest()}])
   tmp=self.path/(uuid.uuid4().hex+'.tmp');_write_new(tmp,self._encode(d))
   if _fault:_fault('journal_synced')
   os.replace(tmp,self.path/'journal.json');self._sync(self.path)
   if _fault:_fault('journal_replaced')
   self._load()
  return self.summary()
 def summary(self):
  return {'format':'bounded-segment-stage-summary-1','identity':self.id,'committed_bytes':self.doc['committed_bytes'],'segments':len(self.doc['segments']),'payload_in_journal':False,'network_requests':0,'installation_ready':False,'apply_authorized':False}
 def read_verified(self):
  """Return freshly verified small staged bytes under cooperative writer lock.
  No live-installation freshness, native generation or apply authority implied.
  """
  with self._lock():
   self._load();need(self.doc['committed_bytes']==self.spec.encoded_size,'stage_object_incomplete')
   raw=b''.join(_read(self.path/s['name'],s['size'])for s in self.doc['segments']);proof=verify_blte(raw,self.spec.public())
   return raw,dict(proof,encoded_sha256=hashlib.sha256(raw).hexdigest(),file_backed_segments=True,installation_ready=False,apply_authorized=False)
 def verified(self):return self.read_verified()[1]
