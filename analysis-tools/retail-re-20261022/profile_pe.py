import sys,json,hashlib,math,re
from pathlib import Path
from collections import Counter
sys.path.insert(0,'/data/re-tools')
import pefile
import argparse
parser=argparse.ArgumentParser(description='Offline PE analysis; never runs input executables')
parser.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'))
parser.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'))
parser.add_argument('--prior-report',type=Path,default=Path('/data/raw/wow-repo-review/hardware_relationship.json'))
args=parser.parse_args()
root=args.input_dir;out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
results=[]
for path in sorted(root.iterdir()):
 b=path.read_bytes();pe=pefile.PE(data=b,fast_load=False)
 sec=[]
 for s in pe.sections:
  raw=s.get_data();counts=Counter(raw);entropy=-sum((n/len(raw))*math.log2(n/len(raw)) for n in counts.values()) if raw else 0
  sec.append({'name':s.Name.rstrip(b'\0').decode(errors='replace'),'rva':hex(s.VirtualAddress),'virtual_size':s.Misc_VirtualSize,'raw_offset':hex(s.PointerToRawData),'raw_size':s.SizeOfRawData,'characteristics':hex(s.Characteristics),'entropy':round(entropy,5)})
 imports=[]
 for lib in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
  imports.append({'dll':lib.dll.decode(errors='replace'),'functions':[{'name':f.name.decode(errors='replace') if f.name else '#'+str(f.ordinal),'iat_rva':hex(f.address-pe.OPTIONAL_HEADER.ImageBase)} for f in lib.imports]})
 exports=[{'name':x.name.decode(errors='replace') if x.name else '#'+str(x.ordinal),'rva':hex(x.address)} for x in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
 needles=['ClientSystemSpec','ClientEngineLogV2','cpu_vendor','cpu_brand','motherboardBiosVersion','telemetry-in.battle.net','telemetry.battle.net','engineSurvey','Security Crash','SSL_write','EncryptMessage','GetSystemFirmwareTable','GetNativeSystemInfo','CPUID','3724']
 matches={}
 for n in needles:
  hit=[];start=0
  while (idx:=b.find(n.encode(),start))>=0:
   try:rva=hex(pe.get_rva_from_offset(idx))
   except Exception:rva=None
   hit.append({'file_offset':hex(idx),'rva':rva});start=idx+len(n)
   if len(hit)>=80:break
  if hit:matches[n]=hit
 info={'name':path.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'sections':sec,'imports':imports,'exports':exports,'unwind_function_count':len(getattr(pe,'DIRECTORY_ENTRY_EXCEPTION',[])),'needle_matches':matches}
 results.append(info)
(out/'pe-profile.json').write_text(json.dumps(results,indent=2)+'\n')
for r in results:
 print(r['name'],'base',r['image_base'],'entry',r['entry_rva'],'unwind',r['unwind_function_count'],'imports',sum(len(x['functions']) for x in r['imports']))
 print('Sections:',[(x['name'],x['raw_size'],x['entropy'],x['characteristics']) for x in r['sections']])
 print('Exports:',r['exports'][:12])
 print('Matched terms:',{k:len(v) for k,v in r['needle_matches'].items()})
 print('Relevant imports:',[(x['dll'],f['name']) for x in r['imports'] for f in x['functions'] if re.search(r'firmware|systeminfo|query|debug|send|wsasend|ssl|encrypt|connect|protect|virtual|regopen|regquery|loadlibrary|getprocaddress',f['name'],re.I)])
