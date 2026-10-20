import json,sys
from pathlib import Path
from google.protobuf import descriptor_pb2,descriptor_pool,message_factory,json_format
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/data/wow-static');b=(root/'raw/Wow.exe').read_bytes(); inv=json.load(open(root/'analysis/telemetry-descriptors.json'))
def load(name):
 d=next(x for x in inv['files'] if x['name']==name);return descriptor_pb2.FileDescriptorProto.FromString(b[int(d['offset'],16):int(d['end_offset_exclusive'],16)])
ext=load('telemetry_extensions.proto')
pool=descriptor_pool.DescriptorPool();pool.AddSerializedFile(descriptor_pb2.DESCRIPTOR.serialized_pb);pool.AddSerializedFile(ext.SerializeToString())
options_class=message_factory.GetMessageClass(pool.FindMessageTypeByName('google.protobuf.MessageOptions'))
print('EXTENSION DEFINITIONS\n',ext)
for filename in ['ClientShared.proto','TelemetrySharedClientImports.proto','ClientSharedImports.proto']:
 f=load(filename)
 print('\nFILE',filename)
 for msg in f.message_type:
  o=options_class.FromString(msg.options.SerializeToString())
  print('MESSAGE',msg.name,'OPTIONS',o)
  if msg.name=='ClientEngineLogV2':
   fields=[{'name':x.name,'number':x.number,'type':x.type,'default':x.default_value,'label':x.label,'options_hex':x.options.SerializeToString().hex()} for x in msg.field]
   r={'message':f.package+'.'+msg.name,'descriptor':filename,'message_options_hex':msg.options.SerializeToString().hex(),'message_options_decoded':json_format.MessageToDict(o,preserving_proto_field_name=True),'fields':fields}
   (root/'trace/engine-message-options.json').write_text(json.dumps(r,indent=2)+'\n')
(root/'trace/telemetry-extensions-descriptor.json').write_text(json.dumps(json_format.MessageToDict(ext,preserving_proto_field_name=True),indent=2)+'\n')
