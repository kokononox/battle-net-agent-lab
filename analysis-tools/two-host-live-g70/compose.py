"""Materialize pinned G69 base plus explicit G70 overlays, without modifying base."""
import json,hashlib
from pathlib import Path
base=Path(__file__).resolve().parent;src=base.with_name('two-host-live-g69');dst=base.with_name('two-host-live-g70-runtime')
OVERLAYS=('hook.js','run.py','control.py','origin_audit.py','origin_control.py','OriginFixture.cs','test_origin.py','README.fa.md')
manifest=json.loads((base/'base-manifest.json').read_text());dst.mkdir(exist_ok=False)
for name,digest in manifest.items():
 if Path(name).name!=name:raise ValueError('invalid_base_name')
 b=(src/name).read_bytes()
 if hashlib.sha256(b).hexdigest()!=digest:raise ValueError('pinned_G69_base_changed')
 if Path(name).suffix!='.json':b=b.replace(b'g69',b'g70').replace(b'G69',b'G70')
 (dst/name).write_bytes(b)
for name in OVERLAYS:(dst/name).write_bytes((base/name).read_bytes())
print('G70 pinned base and explicit overlays verified')
