from pathlib import Path
from pe_manual import PE
import json,struct,hashlib,collections
p=PE(Path('/data/wlab-inputs/wow_loader.dll'));h=hashlib.sha256(p.b).hexdigest();assert h=='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
rows=json.load(open('/data/wlab-export-effects/unwind-inventory.json'))[1]['handler_rows'];out=[];callbacks=collections.Counter()
# Only these handlers use the directly observed count+16-byte-scope-table layout.
for r in rows:
 if r['handler_rva'] not in [0x20069b4,0x2035a08]:continue
 u=r['unwind'];head=p.read(u,4);extra=u+4+((head[2]+1)//2)*4;assert p.u(extra,'<I')==r['handler_rva'];data=extra+4;count=p.u(data,'<I');assert count<4096
 scopes=[]
 for k in range(count):
  start,end,filter_,jump=struct.unpack('<IIII',p.read(data+4+k*16,16));assert 0<=start<end<=0x2800000
  scopes.append({'begin':start,'end':end,'filter_or_finally':filter_,'jump_target':jump,'kind':'finally' if jump==0 else 'except'})
  if filter_ not in [0,1,0xffffffff]:callbacks[filter_]+=1
 out.append({'function_begin':r['begin'],'function_end':r['end'],'handler_rva':r['handler_rva'],'handler_data_rva':data,'scope_count':count,'scopes':scopes})
report={'sha256':h,'layout_evidence':'Handler 0x20069b4 reads table count and 16-byte entries through DispatcherContext.HandlerData; 0x2035a08 delegates to it after cookie check. Layout applicability is limited to these two exact handlers.','tables':out,'callback_counts':{hex(k):v for k,v in callbacks.items()},'unresolved_other_handler_formats':True,'vectored_handlers_not_in_scope':True}
Path('/data/wlab-handler-triage/scope-tables.json').write_text(json.dumps(report,indent=2))
print('tables',len(out),'scope_records',sum(x['scope_count'] for x in out),'callbacks',report['callback_counts'])
