"""Materialize five pinned public metadata fixtures in this source tree; no network/game I/O."""
from pathlib import Path
import base64,json,hashlib
root=Path(__file__).resolve().parent
manifest=json.loads((root/'MANIFEST-SHA256.json').read_text())
items={name:(root/(name+'.b64')).read_text().strip() for name in manifest if (root/(name+'.b64')).is_file()}
assert len(items)==5
for name,encoded in items.items():
 p=Path(name)
 assert p.parts[:2]==('research','fixtures') and '..'not in p.parts and not p.is_absolute()
 raw=base64.b64decode(encoded,validate=True)
 assert hashlib.sha256(raw).hexdigest()==manifest[name]
 path=root/p
 assert not path.is_symlink()
 if path.exists():assert hashlib.sha256(path.read_bytes()).hexdigest()==manifest[name]
 else:
  path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as f:f.write(raw)
print('Five pinned metadata fixtures ready; no network or game access.')
