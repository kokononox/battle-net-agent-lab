"""Extract structural protobuf descriptor metadata offline; never executes target.
Usage: python extract_telemetry_schema.py Wow.exe output.json
Dependency: google.protobuf. Does NOT prove runtime population or network send.
"""
import re,json,sys,hashlib
from pathlib import Path
from google.protobuf.descriptor_pb2 import FileDescriptorProto,FieldDescriptorProto
b=Path(sys.argv[1]).read_bytes()
def vint(p):
 v=0
 for n in range(10):
  if p>=len(b):raise ValueError()
  c=b[p];p+=1;v|=(c&127)<<(7*n)
  if c<128:return v,p
 raise ValueError()
def candidate(start):
 p=start
 while p<len(b) and p<start+4*1024*1024:
  prev=p
  try:
   tag,p=vint(p);field,wire=tag>>3,tag&7
   if not 1<=field<=12 or (wire!=2 and not(field==10 and wire==0)):break
   if wire==2:
    n,p=vint(p)
    if n>4*1024*1024 or p+n>len(b):break
    p+=n
   else:_,p=vint(p)
  except ValueError:break
  try:
   f=FileDescriptorProto.FromString(b[start:p])
   if f.name and f.message_type:yield p,f
  except Exception:pass
  if p<=prev:break
files=[];seen=set(); messages=[]
for m in re.finditer(rb'\x0a[\x01-\x7f][A-Za-z0-9_/.-]{1,126}\.proto',b):
 start=m.start()
 cs=list(candidate(start))
 if not cs:continue
 end,f=cs[-1]
 if not f.name.endswith('.proto') or not f.package.startswith('Blizzard.Telemetry') or f.name in seen:continue
 seen.add(f.name);files.append({'name':f.name,'package':f.package,'offset':hex(start),'end_offset_exclusive':hex(end),'descriptor_sha256':hashlib.sha256(b[start:end]).hexdigest(),'dependencies':list(f.dependency),'top_level_messages':len(f.message_type)})
 def visit(msg,parent):
  name=parent+'.'+msg.name
  fields=[{'name':x.name,'number':x.number,'type':FieldDescriptorProto.Type.Name(x.type),'type_name':x.type_name or None,'label':FieldDescriptorProto.Label.Name(x.label)} for x in msg.field]
  messages.append({'name':name,'descriptor_file':f.name,'fields':fields})
  for c in msg.nested_type:visit(c,name)
 for msg in f.message_type:visit(msg,f.package)
interesting=[]
for msg in messages:
 selected=[x for x in msg['fields'] if re.search(r'(?i)cpu|bios|motherboard|hardware|firmware|osversion|gpu_name',x['name'])]
 if selected:interesting.append({**{k:v for k,v in msg.items() if k!='fields'},'hardware_related_fields':selected,'total_fields':len(msg['fields'])})
result={'schema':'wow-offline-telemetry-descriptor-inventory-1','input_sha256':hashlib.sha256(b).hexdigest(),'files':files,'message_count':len(messages),'hardware_related_messages':interesting,'all_message_structures':messages,'runtime_population_proven':False,'destination_binding_proven':False,'notes':['Embedded descriptors parsed by protobuf, not inferred from nearby strings','No function dataflow reconstruction','No complete protocol or dynamic code coverage']}
Path(sys.argv[2]).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print('Descriptors',len(files),'messages',len(messages))
for x in interesting:
 print(x['name'], 'fields',x['total_fields']);print(', '.join(f"{f['name']}={f['number']}:{f['type']}" for f in x['hardware_related_fields']))
