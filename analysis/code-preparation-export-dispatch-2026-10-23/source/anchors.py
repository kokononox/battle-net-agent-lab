from pathlib import Path
from pe_manual import PE
import json,hashlib,re,struct
out=[]
for name in ['Wow.exe','wow_loader.dll']:
 p=PE(Path('/data/wlab-inputs')/name)
 row={'file':name,'sha256':hashlib.sha256(p.b).hexdigest(),'entry_rva':hex(p.ep),'directories':p.dirs,'sections':p.sections}
 for key,fn in [('imports',p.imports),('tls',p.tls)]:
  try:row[key]=fn()
  except Exception as e:row[key]={'error':str(e)}
 needles=[b'VirtualProtect',b'NtProtectVirtualMemory',b'AddVectoredExceptionHandler',b'RtlAddVectoredExceptionHandler',b'GetProcAddress',b'LdrGetProcedureAddress',b'NtMapViewOfSection',b'FlushInstructionCache']
 row['literal_candidates']=[]
 for term in needles:
  for encoding,needle in [('ascii',term),('utf16',term.decode().encode('utf-16-le'))]:
   for m in re.finditer(re.escape(needle),p.b):
    offset=m.start(); rvas=[s[2]+offset-s[4] for s in p.sections if s[4]<=offset<s[4]+s[3]]
    row['literal_candidates'].append({'name':term.decode(),'encoding':encoding,'offset':offset,'rvas':[hex(v) for v in rvas]})
 out.append(row)
Path('/data/wlab-code-preparation-review/anchors.json').write_text(json.dumps(out,indent=2))
for row in out:
 print(row['file'],'entry',row['entry_rva'],'TLS',row['tls'])
 print('sections',[(s[0],hex(s[2]),s[1],s[3]) for s in row['sections']])
 im=row['imports'];print('imports', [(i['dll'],len(i['entries']),[e['literal_name'] or '#'+str(e['ordinal']) for e in i['entries']][:18]) for i in im] if isinstance(im,list) else im)
 print('literals',row['literal_candidates'][:25])
