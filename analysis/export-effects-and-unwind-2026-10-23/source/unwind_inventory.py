from pathlib import Path
from pe_manual import PE
import struct,json,hashlib,collections
out=[]
for name in ['Wow.exe','wow_loader.dll']:
 p=PE(Path('/data/wlab-inputs')/name);start,size=p.dirs[3];rows=[];errors=[];targets=[]
 for a in range(start,start+size,12):
  begin,end,u=struct.unpack('<III',p.read(a,12))
  try:
   h=p.read(u,4);version=h[0]&7;flags=h[0]>>3;count=h[2];extra=u+4+((count+1)//2)*4
   row={'begin':begin,'end':end,'unwind':u,'version':version,'flags':flags}
   if flags&3 and not flags&4:row['handler_rva']=p.u(extra,'<I');rows.append(row)
   if name=='Wow.exe' and begin in [0x1b14120,0x1b11190,0x33068c0]:
    if flags&4:row['chain']=struct.unpack('<III',p.read(extra,12))
    targets.append(row)
  except Exception as e:errors.append({'begin':begin,'unwind':u,'error':str(e)})
 summary=collections.Counter(row['handler_rva'] for row in rows)
 out.append({'file':name,'sha256':hashlib.sha256(p.b).hexdigest(),'runtime_function_count':size//12,'handler_rows':rows,'handler_counts':{hex(k):v for k,v in summary.items()},'target_rows':targets,'errors':errors,'scope':'PE unwind metadata only; handler RVA is not proof of handler execution or code preparation. Vectored handlers are not enumerated by this metadata.'})
 print(name,'functions',size//12,'handlers', {hex(k):v for k,v in summary.items()},'errors',len(errors),'targets',targets)
Path('/data/wlab-export-effects/unwind-inventory.json').write_text(json.dumps(out,indent=2))
