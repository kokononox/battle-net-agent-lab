"""Bounded file evidence; no private contents, registry or credentials exported."""
import os,sys,json,hashlib,time
from pathlib import Path
root=Path(sys.argv[1]);out=[];total=0
bases=[(root/'stage-temp','staged_temp'),(Path(os.environ['ProgramData'])/'Battle.net','programdata_battle_net'),(Path(os.environ['ProgramData'])/'Blizzard Entertainment','programdata_blizzard'),(Path(os.environ['ProgramFiles(x86)'])/'Battle.net','programfiles_battle_net')]
for base,kind in bases:
 if not base.exists():continue
 for directory,folders,files in os.walk(base,followlinks=False):
  folders[:]=[n for n in folders if not (Path(directory)/n).is_symlink() and not getattr((Path(directory)/n).lstat(),'st_file_attributes',0)&0x400]
  for name in files:
   if len(out)>=256:break
   p=Path(directory)/name
   try:
    st=p.lstat()
    if p.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:continue
    size=st.st_size;digest=None
    if size<=67108864 and total+size<=268435456:digest=hashlib.sha256(p.read_bytes()).hexdigest();total+=size
    label=name if name.lower() in {'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe'} else 'other_file'
    out.append({'root_category':kind,'name':label,'relative_path_sha256':hashlib.sha256(str(p.relative_to(base)).encode()).hexdigest(),'extension':p.suffix.lower() if p.suffix.lower() in {'.exe','.dll','.log','.json','.db','.idx','.data','.ini','.config'} else 'other','bytes':size,'sha256':digest})
   except OSError:continue
  if len(out)>=256:break
(root/'files-evidence.json').write_text(json.dumps({'files':out,'truncated':len(out)>=256,'hashed_bytes':total,'installation_proven':False}))
