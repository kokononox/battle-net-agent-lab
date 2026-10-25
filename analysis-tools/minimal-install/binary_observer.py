"""Wait for stable file candidates before read-only trust observation.
A failed observation never creates accepted signature evidence. No UI retries here.
"""
import hashlib
from signature_observation import probe,result
import native_version
class BinaryObserver:
 def __init__(self,verify=probe,version=native_version.query):self.candidates={};self.verify=verify;self.version=version
 def sample(self,path,kind,obs,env,now):
  try:
   if obs.is_reparse(path):return None,result('file_busy')
   size=path.stat().st_size
   if not 0<size<=128*1024**2:return None,result('invalid_size')
   data=path.read_bytes()
   if len(data)!=size:return None,result('file_changed')
   digest=hashlib.sha256(data).hexdigest();key=str(path);previous=self.candidates.get(key)
   if previous is None or previous[0]!=digest:
    self.candidates[key]=(digest,now);return None,result('waiting_stability')
   if now-previous[1]<10:return None,result('waiting_stability')
   sig=self.verify(path,env);version,vstate=self.version(path)
   if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
    self.candidates.pop(key,None);return None,result('file_changed')
   accepted=sig['status']=='accepted'
   return dict(kind=kind,sha256=digest,bytes=len(data),signature_accepted=accepted,file_version=version,version_status=vstate),sig
  except OSError:return None,result('file_busy')
