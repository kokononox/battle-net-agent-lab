"""Read pinned Git blob bytes, compose G69 base plus G70 trace plus G71 overlays."""
import json,hashlib,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent;dst=base.with_name('two-host-live-g71-runtime');dst.mkdir(exist_ok=False)
def blob(folder,name,digest,previous):
 if Path(name).name!=name:raise ValueError('invalid_base_name')
 r=subprocess.run(['git','show','HEAD:analysis-tools/'+folder+'/'+name],cwd=base.parents[1],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True);b=r.stdout
 if hashlib.sha256(b).hexdigest()!=digest:raise ValueError('pinned_base_changed')
 if Path(name).suffix!='.json':b=b.replace(previous.encode(),b'g71').replace(previous.upper().encode(),b'G71')
 return b
for n,d in json.loads((base/'base-manifest.json').read_text()).items():(dst/n).write_bytes(blob('two-host-live-g69',n,d,'g69'))
for n,d in json.loads((base/'g70-overlay-manifest.json').read_text()).items():(dst/n).write_bytes(blob('two-host-live-g70',n,d,'g70'))
for n in ('run.py','origin_audit.py','response_origin.py','test_response_origin.py','PublicReference.ps1','tls_control.py','TlsFixture.cs','README.fa.md'):(dst/n).write_bytes((base/n).read_bytes())
print('G71 pinned Git-blob bases and explicit overlays verified')
