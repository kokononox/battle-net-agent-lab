"""Pinned Git blobs, never Windows working-tree text, plus explicit G72 overlays."""
import json,hashlib,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent;dst=base.with_name('two-host-live-g72-runtime');dst.mkdir(exist_ok=False)
def blob(folder,name,digest,previous):
 if Path(name).name!=name:raise ValueError('invalid_base_name')
 r=subprocess.run(['git','show','HEAD:analysis-tools/'+folder+'/'+name],cwd=base.parents[1],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True);b=r.stdout
 if hashlib.sha256(b).hexdigest()!=digest:raise ValueError('pinned_base_changed')
 if Path(name).suffix!='.json':b=b.replace(previous.encode(),b'g72').replace(previous.upper().encode(),b'G72')
 return b
for folder,manifest,previous in [('two-host-live-g69','base-manifest.json','g69'),('two-host-live-g70','g70-overlay-manifest.json','g70'),('two-host-live-g71','g71-overlay-manifest.json','g71')]:
 for n,d in json.loads((base/manifest).read_text()).items():(dst/n).write_bytes(blob(folder,n,d,previous))
for n in ('run.py','response_origin.py','schema_attribution.py','test_schema_attribution.py','tls_control.py','TlsFixture.cs','README.fa.md','public-schema-reference.json'):(dst/n).write_bytes(subprocess.run(['git','show','HEAD:analysis-tools/two-host-live-g72/'+n],cwd=base.parents[1],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout)
print('G72 pinned Git-blob bases and explicit overlays verified')
