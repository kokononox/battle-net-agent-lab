"""Local diagnostics I/O only. No firewall, VPN or route operations."""
from pathlib import Path
import hashlib,json,os,uuid
ROOT=Path(__file__).resolve().parents[1]
def safe(path):
 p=Path(path).absolute()
 for x in (p,*p.parents):
  if x.exists() or x.is_symlink():
   st=x.lstat()
   if x.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:raise ValueError('symlink_or_reparse_path_rejected')
 return p
def atomic(path,value):
 path=safe(path);tmp=path.with_name(path.name+'.next-'+uuid.uuid4().hex)
 try:
  with tmp.open('x',encoding='utf-8') as f:
   json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()
def verify():
 for name,want in json.loads((ROOT/'MANIFEST-SHA256.json').read_text()).items():
  q=Path(name)
  if q.is_absolute() or '..' in q.parts:raise ValueError('invalid_manifest_path')
  if hashlib.sha256(safe(ROOT/q).read_bytes()).hexdigest()!=want:raise ValueError('package_changed:'+name)
def admit(request,output):
 request=safe(request);output=safe(output);base=safe(ROOT/'private-state/jobs')
 if base not in request.parents or base not in output.parents or request.parent!=output.parent or request.stat().st_size>8192:raise ValueError('request_scope_or_size')
 q=json.loads(request.read_text('utf-8-sig'))
 from https_common import https_endpoint
 from traffic_common import challenge
 if set(q)!={'url','address','challenge'}:raise ValueError('request_keys')
 https_endpoint(q['url'],q['address']);challenge(q['challenge'])
 return q,output
