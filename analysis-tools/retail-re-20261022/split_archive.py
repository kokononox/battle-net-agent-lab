from pathlib import Path
import json,hashlib
src=Path('/data/.agent-service/files/14ba1c1c-cb92-4b7f-8663-205e371ba5f8/_retail_.zip');out=Path('/data/retail-70448-split');manifest={'format':'byte-split-v1','original_filename':'_retail_.zip','original_bytes':src.stat().st_size,'original_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'part_bytes_limit':20000000,'parts':[]}
whole=hashlib.sha256()
with src.open('rb') as f:
 i=1
 while b:=f.read(manifest['part_bytes_limit']):
  name=f'_retail_.zip.part{i:03d}';(out/name).write_bytes(b);whole.update(b)
  manifest['parts'].append({'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()});i+=1
assert whole.hexdigest()==manifest['original_sha256']
assert sum(x['bytes'] for x in manifest['parts'])==manifest['original_bytes']
assert all(x['bytes']<25000000 for x in manifest['parts'])
manifest['contained_files']=[{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(Path('/data/raw/wow-retail-20261022').iterdir())]
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Parts:',len(manifest['parts']),'Sizes:',[x['bytes'] for x in manifest['parts']]);print('Reassembled SHA-256 verified:',whole.hexdigest())
