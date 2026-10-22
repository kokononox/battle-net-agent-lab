"""Relocation-backed registration and layout candidates, not recovered runtime behavior."""
from pathlib import Path
import argparse,sys,os,json,struct,hashlib
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile
p=argparse.ArgumentParser();p.add_argument('--old',type=Path,default=Path('/data/raw/wow-retail-old/Wow.exe'));p.add_argument('--baseline',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();out=a.out
report=json.loads((out/'descriptor-comparison.json').read_text());results={}
for label,path in [('old',a.old),('baseline',a.baseline)]:
 b=path.read_bytes();pe=pefile.PE(data=b,fast_load=True);pe.parse_data_directories(directories=[5,2]);base=pe.OPTIONAL_HEADER.ImageBase
 versions=[]
 for group in getattr(pe,'FileInfo',[]):
  for item in group:
   if getattr(item,'Key',None)==b'StringFileInfo':
    for table in item.StringTable:
     versions.append({k.decode(errors='replace'):v.decode(errors='replace') for k,v in table.entries.items() if k in [b'FileVersion',b'ProductVersion']})
 reloc={e.rva for block in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',[]) for e in block.entries if e.type==10}
 u32=lambda r:struct.unpack('<I',pe.get_data(r,4))[0]
 u64=lambda r:struct.unpack('<Q',pe.get_data(r,8))[0]
 selected=[]
 for desc in report[label]['selected_messages']:
  name=desc['message'];drva=int(desc['descriptor_rva'],16);candidates=[]
  for r in reloc:
   if u64(r)==base+drva and r>=8 and u32(r-4)==desc['descriptor_size']:candidates.append(r-8)
  assert len(candidates)==1,(name,candidates);reg=candidates[0]
  index=1 if name.endswith('.ClientSystemSpec') else 0
  schemas=u64(reg+0x30)-base;instances=u64(reg+0x38)-base;offsets=u64(reg+0x40)-base
  oi,hi,si,size=struct.unpack('<iiiI',pe.get_data(schemas+16*index,16));inst=u64(instances+8*index)-base
  fields=[]
  for j,f in enumerate(desc['fields']):
   off=u32(offsets+4*(oi+8+j));bit=u32(offsets+4*(hi+j));assert off<size and bit<len(desc['fields'])
   fields.append({'name':f['name'],'number':f['number'],'object_offset_candidate':hex(off),'hasbit_index_candidate':bit})
  vt=u64(inst)-base;methods=[]
  for j in range(32):
   v=u64(vt+8*j)-base;s=pe.get_section_by_rva(v) if v>=0 else None
   if not s or not s.Characteristics&0x20000000:break
   methods.append({'slot':j,'target_rva':hex(v),'first_16_bytes':pe.get_data(v,16).hex()})
  selected.append({'message':name,'descriptor_rva':hex(drva),'registration_table_candidate_rva':hex(reg),'relocation_backed_descriptor_pointer_rva':hex(reg+8),'migration_schema_rva':hex(schemas+16*index),'offset_array_rva':hex(offsets),'candidate_object_size':size,'default_instance_rva':hex(inst),'vtable_candidate_rva':hex(vt),'method_candidates_contiguous_run':methods,'fields':fields,'runtime_roles_unresolved':True})
 results[label]={'source_sha256':hashlib.sha256(b).hexdigest(),'version_resources':versions,'messages':selected}
comparisons=[]
for o in results['old']['messages']:
 n=next(x for x in results['baseline']['messages'] if x['message']==o['message'])
 comparisons.append({'message':o['message'],'candidate_object_size_old':o['candidate_object_size'],'candidate_object_size_baseline':n['candidate_object_size'],'field_offsets_and_hasbits_identical':o['fields']==n['fields'],'method_candidate_RVAs_identical':[x['target_rva'] for x in o['method_candidates_contiguous_run']]==[x['target_rva'] for x in n['method_candidates_contiguous_run']],'limits':'Matching layout data is not semantic equivalence or permission to reuse function addresses.'})
results['comparison']=comparisons;results['layout_model']='Upstream protobuf v30.1 layout candidate, not proven ABI identity of protobuf_blz';results['hardware_population_serialization_or_send_proven']=False
(out/'registration-comparison.json').write_text(json.dumps(results,indent=2)+'\n')
print('Versions',results['old']['version_resources'],results['baseline']['version_resources']);print(json.dumps(comparisons,indent=2))
