"""Offline, non-executing PE inventory; strings/xrefs are NOT dataflow/upload proof.
Requires pefile==2024.8.26, capstone==5.0.9. Usage: python static_inventory.py INPUT_DIR OUTPUT_DIR
"""
import sys, pathlib, re, json, hashlib, math, collections, bisect
try:
 import pefile
 from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
 sys.path.insert(0,'/data/wow-static/vendor')
 import pefile
 from capstone import Cs, CS_ARCH_X86, CS_MODE_64
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); out.mkdir(parents=True,exist_ok=True)
patterns={
 'destination':re.compile(r'(?i)(?:[a-z0-9_-]+\.)+(?:blizzard\.com|battle\.net)|(?:[a-z0-9_-]+\.)*(?:blizzard\.com|battle\.net)'),
 'hardware':re.compile(r'(?i)\b(?:bios|smbios|baseboard|processor|cpu|hardware|systemmanufacturer|systemproductname|firmware|machineguid|cpuid)\b|BIOSVersion|Win32_(?:BIOS|Processor|BaseBoard|ComputerSystem)|GetSystemFirmwareTable|SystemBios|ProcessorNameString|cpu[_ -]?(?:model|name|brand)|bios[_ -]?(?:version|date|vendor)'),
 'telemetry':re.compile(r'(?i)telemetry|wow\.ingest|gdp\.blizzard|hardware[_ .]?(?:info|survey|spec)|system[_ .]?survey|device[_ .]?fingerprint'),
}
results=[]
for path in sorted(src.iterdir()):
 if path.suffix.lower() not in ('.exe','.dll'):continue
 data=path.read_bytes(); pe=pefile.PE(data=data,fast_load=True)
 dirs=['IMAGE_DIRECTORY_ENTRY_IMPORT','IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT','IMAGE_DIRECTORY_ENTRY_EXPORT','IMAGE_DIRECTORY_ENTRY_RESOURCE','IMAGE_DIRECTORY_ENTRY_EXCEPTION','IMAGE_DIRECTORY_ENTRY_DEBUG']
 pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[x] for x in dirs])
 base=pe.OPTIONAL_HEADER.ImageBase
 def dec(x):return x.decode('utf8','replace') if isinstance(x,bytes) else str(x)
 imports=[]; iats={}
 for attr in ('DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT'):
  for entry in getattr(pe,attr,[]):
   names=[]
   for imp in entry.imports:
    n=dec(imp.name) if imp.name else '#'+str(imp.ordinal); names.append(n); iats[imp.address]=dec(entry.dll)+'!'+n
   imports.append({'dll':dec(entry.dll),'delayed':attr.endswith('DELAY_IMPORT'),'symbols':names})
 sections=[]
 for s in pe.sections:
  sections.append({'name':dec(s.Name.rstrip(b'\0')),'rva':hex(s.VirtualAddress),'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData,'entropy':round(s.get_entropy(),3),'executable':bool(s.Characteristics&0x20000000),'writable':bool(s.Characteristics&0x80000000)})
 version={}
 for group in getattr(pe,'FileInfo',[]):
  for entry in group:
   for st in getattr(entry,'StringTable',[]):version.update({dec(k):dec(v) for k,v in st.entries.items()})
 strings={k:[] for k in patterns}; counts=collections.Counter(); targets={}
 for encoding,pat in [('ascii',rb'[\x20-\x7e]{5,}'),('utf16le',rb'(?:[\x20-\x7e]\x00){5,}')]:
  for m in re.finditer(pat,data):
   if len(m[0])>2048:continue
   text=m[0].decode('ascii' if encoding=='ascii' else 'utf-16le')
   for cat,p in patterns.items():
    if not p.search(text):continue
    counts[cat]+=1
    if len(strings[cat])>=500:continue
    try:rva=pe.get_rva_from_offset(m.start())
    except Exception:rva=None
    item={'offset':hex(m.start()),'rva':hex(rva) if rva is not None else None,'encoding':encoding,'text':text[:512]}; strings[cat].append(item)
    if rva is not None and cat in ('hardware','telemetry'):targets[base+rva]=item
 interesting_imports={k:v for k,v in iats.items() if re.search(r'(?i)Firmware|SystemInfo|RegQuery|RegGet|GetAdapters|WinHttp|HttpSend|InternetWrite|send$|WSASend|EncryptMessage|SSL_write|GetProcAddress|LoadLibrary',v)}
 # Candidate xrefs: exact instruction-boundary decode of RIP-relative LEA/MOV or indirect CALL.
 # Linear byte search can start inside another instruction; these are candidates, NOT CFG proof.
 md=Cs(CS_ARCH_X86,CS_MODE_64); refs=[]; refcount=0
 funcs=sorted((e.struct.BeginAddress,e.struct.EndAddress) for e in getattr(pe,'DIRECTORY_ENTRY_EXCEPTION',[])); starts=[x[0] for x in funcs]
 def fun(rva):
  i=bisect.bisect_right(starts,rva)-1
  return {'begin_rva':hex(funcs[i][0]),'end_rva':hex(funcs[i][1])} if i>=0 and rva<funcs[i][1] else None
 for sec in pe.sections:
  if pe.FILE_HEADER.Machine != 0x8664 or not sec.Characteristics&0x20000000:continue
  code=sec.get_data()
  for m in re.finditer(rb'(?:[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]|\xff\x15)[\x00-\xff]{4}',code):
   blob=m[0]; va=base+sec.VirtualAddress+m.start(); target=va+len(blob)+int.from_bytes(blob[-4:],'little',signed=True)
   if target not in targets and target not in interesting_imports:continue
   ins=next(md.disasm(blob,va,count=1),None)
   if not ins or ins.size!=len(blob):continue
   refcount+=1
   if len(refs)>=180:continue
   refs.append({'instruction_rva':hex(va-base),'instruction':ins.mnemonic+' '+ins.op_str,'target_rva':hex(target-base),'target_string':targets.get(target,{}).get('text'),'target_import':interesting_imports.get(target),'containing_unwind_range':fun(va-base)})
 secdir=pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
 clr=pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']]
 exports=[{'name':dec(e.name) if e.name else None,'ordinal':e.ordinal,'rva':hex(e.address)} for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])][:100]
 debug=[]
 for e in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
  d=getattr(e,'entry',None); pdb=getattr(d,'PdbFileName',None)
  if pdb:debug.append({'pdb_basename':dec(pdb.rstrip(b'\0')).replace('\\','/').split('/')[-1]})
 r={'file':path.name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'machine':hex(pe.FILE_HEADER.Machine),'image_base':hex(base),'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'managed_clr_directory_present':bool(clr.VirtualAddress),'version':version,'sections':sections,'certificate_table_bytes':secdir.Size,'certificate_present_is_not_trust_verification':True,'exports':exports,'imports':imports,'debug':debug,'string_matches':strings,'string_match_total':dict(counts),'string_cap_per_category':500,'candidate_xref_count':refcount,'candidate_xrefs':refs,'candidate_xref_cap':180,'unwind_function_count':len(funcs),'executed':False,'limitations':['String presence is not use or upload proof','RIP candidates are not validated control-flow or data-flow','Indirect/dynamic/encoded references can be missed','No original source reconstruction or complete decompilation','No online certificate trust validation']}
 (out/(path.name+'.json')).write_text(json.dumps(r,ensure_ascii=False,indent=2));results.append({k:r[k] for k in ['file','size','sha256','machine','managed_clr_directory_present','version','string_match_total','candidate_xref_count']})
 print(path.name, r['sha256'],r['string_match_total'],refcount,flush=True)
(out/'summary.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
