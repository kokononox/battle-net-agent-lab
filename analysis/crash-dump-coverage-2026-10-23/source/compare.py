"""Compare captured, file-backed executable sections, without exporting memory."""
from inspect_dump import Dump,D,sha
from pe_manual import PE
import json,struct,os
pins={'Wow.exe':'1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a','wow_loader.dll':'c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'}
inputs={};metadata={}
for name,pin in pins.items():
 p=PE(__import__('pathlib').Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/name);assert sha(p.b)==pin;inputs[name.lower()]=p
 off=struct.unpack_from('<I',p.b,0x3c)[0];opt=off+24;sections=opt+struct.unpack_from('<H',p.b,off+20)[0];ex=[]
 for i,s in enumerate(p.sections):
  flags=struct.unpack_from('<I',p.b,sections+i*40+36)[0]
  if flags&0x20000000:ex.append({'name':s[0],'rva':s[2],'length':s[3]})
 dr,sz=p.dirs[6];cvs=[]
 for i in range(sz//28):
  _,_,_,_,typ,n,a,fo=struct.unpack('<IIHHIIII',p.read(dr+28*i,28))
  if typ==2:cvs.append(sha(p.b[fo:fo+n]))
 metadata[name.lower()]={'input_sha256':pin,'timestamp':struct.unpack_from('<I',p.b,off+8)[0],'size_image':struct.unpack_from('<I',p.b,opt+56)[0],'checksum':struct.unpack_from('<I',p.b,opt+64)[0],'cv_sha256s':cvs,'executable_sections':ex}
report={'disk_identity':metadata,'dumps':[]}
for f in sorted((D/'work').glob('*.dmp')):
 md=Dump(f.read_bytes());mods=md.modules();ranges=md.ranges();r,s=md.streams[6];code=struct.unpack('<I',md.read(r+8,4))[0];address=struct.unpack('<Q',md.read(r+24,8))[0]
 owners=[m for m in mods if m['base']<=address<m['base']+m['size']];exc={'code':hex(code),'module':owners[0]['name'] if len(owners)==1 else None,'rva':hex(address-owners[0]['base']) if len(owners)==1 else None};raw,pieces=md.memory(address,32,ranges);exc['32_bytes_present']=raw is not None;exc['bytes_sha256']=sha(raw) if raw else None
 rr={'name':f.name,'exception':exc,'modules':[]}
 for m in mods:
  key=m['name'].lower()
  if key not in inputs:continue
  p=inputs[key];meta=metadata[key];ident={'timestamp_equal':m['timestamp']==meta['timestamp'],'size_image_equal':m['size']==meta['size_image'],'checksum_equal':m['checksum']==meta['checksum'],'codeview_equal':m['cv_sha256'] in meta['cv_sha256s']}
  chunks=[]
  for sec in meta['executable_sections']:
   start=m['base']+sec['rva'];end=start+sec['length']
   for a,n,o,typ in ranges:
    lo=max(start,a);hi=min(end,a+n)
    if lo>=hi:continue
    rva=lo-m['base'];b=md.read(o+lo-a,hi-lo);disk=p.read(rva,hi-lo)
    chunks.append({'section':sec['name'],'rva':hex(rva),'length':len(b),'runtime_sha256':sha(b),'disk_sha256':sha(disk),'different_bytes':sum(x!=y for x,y in zip(b,disk))})
  rr['modules'].append({'name':m['name'],'identity_checks':ident,'executable_overlap_fragments':chunks,'captured_executable_bytes_sum':sum(c['length'] for c in chunks),'different_bytes_sum':sum(c['different_bytes'] for c in chunks)})
 report['dumps'].append(rr)
(D/'reports/comparison.json').write_text(json.dumps(report,indent=2)+'\n')
for d in report['dumps']:
 print(d['name'],d['exception'])
 for m in d['modules']:print(m['name'],m['identity_checks'],'fragments',len(m['executable_overlap_fragments']),'codebytes',m['captured_executable_bytes_sum'],'different',m['different_bytes_sum'])
