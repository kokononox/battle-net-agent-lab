"""Rebuild original ZIP after verifying every part. Never executes game files."""
from pathlib import Path
import hashlib,json,os,sys,tempfile

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  while data:=f.read(1024*1024):h.update(data)
 return h.hexdigest()

def rebuild(folder):
 folder=Path(folder).resolve();m=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
 if m.get('format')!='byte-split-v1':raise ValueError('Unsupported manifest')
 name=m['original_filename']
 if Path(name).name!=name or name!='_retail_.zip':raise ValueError('Unsafe output filename')
 parts=m['parts']
 if len(parts)!=5:raise ValueError('Expected five parts')
 for i,p in enumerate(parts,1):
  if p['name']!=f'_retail_.zip.part{i:03d}':raise ValueError('Invalid part order/name')
  q=folder/p['name']
  if q.stat().st_size!=p['bytes'] or sha(q)!=p['sha256']:raise ValueError(f'Part verification failed: {p["name"]}')
 targetdir=folder/'rebuilt';targetdir.mkdir(exist_ok=True);target=targetdir/name
 if target.exists():raise FileExistsError('Output exists; it was not overwritten')
 fd,tmp=tempfile.mkstemp(prefix='.rebuild-',dir=targetdir);h=hashlib.sha256();total=0
 try:
  with os.fdopen(fd,'wb') as out:
   for p in parts:
    with (folder/p['name']).open('rb') as f:
     while data:=f.read(1024*1024):out.write(data);h.update(data);total+=len(data)
   out.flush();os.fsync(out.fileno())
  if total!=m['original_bytes'] or h.hexdigest()!=m['original_sha256']:raise ValueError('Final ZIP verification failed')
  # Use exclusive creation rather than replacing an existing ZIP.
  with target.open('xb') as out,open(tmp,'rb') as src:
   while data:=src.read(1024*1024):out.write(data)
  if sha(target)!=m['original_sha256']:raise ValueError('Output verification failed')
  return target
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
if __name__=='__main__':
 try:
  p=rebuild(Path(__file__).parent);print('VERIFIED:',p);print('No executable was run.')
 except Exception as e:print('STOP:',str(e),file=sys.stderr);sys.exit(1)
