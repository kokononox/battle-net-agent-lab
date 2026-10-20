"""Bounded offline metadata reference inventory; not runtime execution/dataflow proof."""
import sys,json,struct,re,bisect
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
R=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/data/wow-static');OUT=R/'trace'
needles={'Wow.exe':[b'ClientEngineLogV2',b'https://wow.ingest.gdp.blizzard.com',b'cpu_brand',b'motherboardBiosVersion',b'SharedTelemetry',b'TelemetryConfig',b'LogClientEngine',b'ClientEngineLog',b'https://telemetry-in.battle.net',b'ClientSystemSpec'], 'wow_loader.dll':[b'https://telemetry-in.battle.net/',b'GetSystemFirmwareTable',b'ProcessorNameString',b'telemetry-sdk-cpp/',b'Context_HostInfo',b'host_name',b'cpu_brand',b'bios']}
result={'method':'Exact byte locations + absolute VA pointer refs + x64 RIP address candidates; NOT dataflow','files':[]}
for filename,targets in needles.items():
 b=(R/'raw'/filename).read_bytes();pe=pefile.PE(data=b,fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
 sec=lambda rva:next((s.Name.rstrip(b'\0').decode() for s in pe.sections if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)),None)
 exc=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]; raw=pe.get_data(exc.VirtualAddress,exc.Size); ranges=sorted((a,z) for a,z,u in struct.iter_unpack('<III',raw[:len(raw)//12*12]) if 0<a<z<pe.OPTIONAL_HEADER.SizeOfImage);starts=[a for a,z in ranges]
 def fun(rva):
  i=bisect.bisect_right(starts,rva)-1
  return {'begin_rva':hex(ranges[i][0]),'end_rva':hex(ranges[i][1])} if i>=0 and rva<ranges[i][1] else None
 def off_rva(off):
  try:return pe.get_rva_from_offset(off)
  except Exception:return None
 targets_map={}; records=[]
 for t in targets:
  hits=[]
  for m in re.finditer(re.escape(t),b):
   o=m.start();rva=off_rva(o)
   if rva is None:continue
   prior=b.rfind(b'\0',max(0,o-160),o);start=prior+1 if prior>=0 else max(0,o-160);end=b.find(b'\0',o,min(len(b),o+220));end=end if end!=-1 else min(o+200,len(b))
   context=b[start:min(end,start+512)].decode('ascii','replace');context=re.sub(r'[^\x20-\x7e]','.',context)
   targets_map[base+rva]={'needle':t.decode(),'hit_rva':hex(rva),'interior_string':context}
   ptrs=[]
   for p in re.finditer(re.escape(struct.pack('<Q',base+rva)),b):
    prva=off_rva(p.start())
    if prva is not None:ptrs.append({'offset':hex(p.start()),'rva':hex(prva),'section':sec(prva),'unwind_function':fun(prva)})
   hits.append({'offset':hex(o),'rva':hex(rva),'section':sec(rva),'context':context,'absolute_pointer_refs':ptrs[:50],'absolute_pointer_ref_count':len(ptrs)})
   if len(hits)>=40:break
  records.append({'needle':t.decode(),'hits':hits})
 refs=[];md=Cs(CS_ARCH_X86,CS_MODE_64)
 for s in pe.sections:
  if not s.Characteristics&0x20000000:continue
  code=s.get_data()
  for m in re.finditer(rb'[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d][\x00-\xff]{4}',code):
   va=base+s.VirtualAddress+m.start();tar=va+7+int.from_bytes(m[0][-4:],'little',signed=True)
   if tar not in targets_map:continue
   ins=next(md.disasm(m[0],va,count=1),None)
   if ins and ins.size==7:refs.append({'instruction_rva':hex(va-base),'instruction':ins.mnemonic+' '+ins.op_str,'target':targets_map[tar],'unwind_function':fun(va-base)})
 # A short entry disassembly is NOT considered reachable-call-graph recovery.
 er=pe.OPTIONAL_HEADER.AddressOfEntryPoint;entry=list(md.disasm(pe.get_data(er,64),base+er,count=12))
 ent=[{'rva':hex(i.address-base),'instruction':i.mnemonic+' '+i.op_str} for i in entry]
 r={'file':filename,'image_base':hex(base),'entry_rva':hex(er),'entry_decode_unvalidated':ent,'target_records':records,'rip_candidates':refs}
 result['files'].append(r)
 print(filename,'target hits',sum(len(x['hits']) for x in records),'RIP candidates',len(refs),flush=True)
(OUT/'target-references.json').write_text(json.dumps(result,indent=2)+'\n')
