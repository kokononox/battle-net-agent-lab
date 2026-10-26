"""Pinned Git blobs, never Windows working-tree text, plus explicit G73 overlays."""
import json,hashlib,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent;dst=base.with_name('two-host-live-g73-runtime');dst.mkdir(exist_ok=False)
def blob(folder,name,digest,previous):
 if Path(name).name!=name:raise ValueError('invalid_base_name')
 r=subprocess.run(['git','show','HEAD:analysis-tools/'+folder+'/'+name],cwd=base.parents[1],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True);b=r.stdout
 if hashlib.sha256(b).hexdigest()!=digest:raise ValueError('pinned_base_changed')
 if Path(name).suffix!='.json':b=b.replace(previous.encode(),b'g73').replace(previous.upper().encode(),b'G73')
 return b
for folder,manifest,previous in [('two-host-live-g69','base-manifest.json','g69'),('two-host-live-g70','g70-overlay-manifest.json','g70'),('two-host-live-g71','g71-overlay-manifest.json','g71'),('two-host-live-g72','g72-overlay-manifest.json','g72')]:
 for n,d in json.loads((base/manifest).read_text()).items():(dst/n).write_bytes(blob(folder,n,d,previous))
for n in ('download_path_audit.py','test_full_object_range.py','README.fa.md'):(dst/n).write_bytes(subprocess.run(['git','show','HEAD:analysis-tools/two-host-live-g73/'+n],cwd=base.parents[1],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout)
print('G73 pinned Git-blob bases and explicit overlays verified')
