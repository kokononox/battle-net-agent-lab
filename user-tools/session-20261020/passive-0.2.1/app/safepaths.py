from pathlib import Path
import os,stat

def safe_path(path):
 p=Path(os.path.abspath(path))
 if str(p).startswith('\\\\') or '..' in p.parts:raise ValueError('unsafe_path')
 if os.name=='nt' and ':' in str(p)[2:]:raise ValueError('alternate_stream_refused')
 for q in (p,*p.parents):
  try:s=q.lstat()
  except FileNotFoundError:continue
  if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&0x400:raise ValueError('reparse_path_refused')
 return p
