"""Recover static telemetry descriptors from two files; no native execution."""
from pathlib import Path
import argparse,sys,os,json,hashlib,re
sys.path.insert(0,os.environ.get('RE_TOOLS','/data/re-tools'))
import pefile
from google.protobuf import descriptor_pb2
from google.protobuf.message import DecodeError
p=argparse.ArgumentParser();p.add_argument('--old',type=Path,default=Path('/data/raw/wow-retail-old/Wow.exe'));p.add_argument('--baseline',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args()
def collect(path):
 b=path.read_bytes();pe=pefile.PE(data=b,fast_load=True)
 def vint(pos):
  n=0
  for j in range(10):
   x=b[pos];pos+=1;n|=(x&127)<<(7*j)
   if x<128:return n,pos
  raise ValueError('varint')
 def endof(start):
  pos=start;seen=False
  while pos<len(b):
   before=pos;tag,pos=vint(pos);f=tag>>3;wire=tag&7
   if not 1<=f<=14 or (f==1 and seen):return before
   if f==1:seen=True
   if wire==0:_,pos=vint(pos)
   elif wire==1:pos+=8
   elif wire==2:n,pos=vint(pos);pos+=n
   elif wire==5:pos+=4
   else:return before
   if pos>len(b):return before
  return pos
 found={}
 for m in re.finditer(rb'([A-Za-z][A-Za-z0-9_/.-]{1,160}\.proto)',b):
  for start in range(max(0,m.start()-4),m.start()):
   if b[start]!=10:continue
   try:
    n,pos=vint(start+1)
    if pos!=m.start() or n!=len(m[1]):continue
    end=endof(start);blob=b[start:end];fd=descriptor_pb2.FileDescriptorProto();fd.ParseFromString(blob)
    if fd.name.encode()!=m[1] or not fd.package.startswith('Blizzard.Telemetry'):continue
    for msg in fd.message_type:
     if msg.name not in ('ClientSystemSpec','ClientEngineLogV2'):continue
     key=fd.package+'.'+msg.name
     entry={'message':key,'descriptor_file':fd.name,'descriptor_file_offset':hex(start),'descriptor_rva':hex(pe.get_rva_from_offset(start)),'descriptor_size':len(blob),'descriptor_sha256':hashlib.sha256(blob).hexdigest(),'message_options_hex':msg.options.SerializeToString().hex(),'fields':[{'index':j,'name':f.name,'number':f.number,'label':f.label,'type':f.type,'type_name':f.type_name,'options_hex':f.options.SerializeToString().hex()} for j,f in enumerate(msg.field)]}
     if key in found:assert found[key]['descriptor_sha256']==entry['descriptor_sha256']
     else:found[key]=entry
   except (ValueError,IndexError,DecodeError):continue
   except Exception as e:
    # Binary false candidates need not be valid protobuf; expected decode failures are ignored.
    if type(e).__name__=='DecodeError':continue
    raise
 return {'source_sha256':hashlib.sha256(b).hexdigest(),'selected_messages':list(found.values())}
old=collect(a.old);base=collect(a.baseline);comparison=[]
oldmap={x['message']:x for x in old['selected_messages']};basemap={x['message']:x for x in base['selected_messages']}
for name in sorted(set(oldmap)|set(basemap)):
 o=oldmap.get(name);n=basemap.get(name)
 comparison.append({'message':name,'present_old':o is not None,'present_baseline':n is not None,'field_count_old':len(o['fields']) if o else None,'field_count_baseline':len(n['fields']) if n else None,'field_definitions_and_options_identical':o['fields']==n['fields'] if o and n else False,'entire_descriptor_bytes_identical':o['descriptor_sha256']==n['descriptor_sha256'] if o and n else False,'message_options_identical':o['message_options_hex']==n['message_options_hex'] if o and n else False})
report={'old':old,'baseline':base,'comparison':comparison,'runtime_population_or_send_proven':False,'code_or_offsets_interchangeable_proven':False,'limits':'Static descriptor definitions only; identical schema does not prove identical compiled layout, code, active usage or transport.'}
(a.out/'descriptor-comparison.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(comparison,indent=2))
