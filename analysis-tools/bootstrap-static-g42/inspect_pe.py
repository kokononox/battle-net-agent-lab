"""Bounded static PE resources, strings, certificates and protobuf descriptors.
No loader, emulator, installer execution or resource URL requests.
"""
import hashlib,json,re,struct
from pathlib import Path
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes
from google.protobuf import descriptor_pb2
BASE=Path(__file__).resolve().parents[2];PRIVATE=BASE/'private';REPORT=BASE/'reports/bootstrap-static-g42'
b=(PRIVATE/'Battle.net-Setup.exe').read_bytes()
if len(b)>32*1024*1024 or b[:2]!=b'MZ':raise ValueError('input_bound')
def span(off,n):
 if off<0 or n<0 or off+n>len(b):raise ValueError('span_bound')
 return b[off:off+n]
def u16(o):return struct.unpack('<H',span(o,2))[0]
def u32(o):return struct.unpack('<I',span(o,4))[0]
pe=u32(0x3c)
if span(pe,4)!=b'PE\0\0':raise ValueError('pe_magic')
coff=pe+4;opt=coff+20;machine=u16(coff);nsec=u16(coff+2);optlen=u16(coff+16)
if not 1<=nsec<=96 or u16(opt)!=0x10b or optlen<224:raise ValueError('unsupported_pe')
sections=[]
for i in range(nsec):
 o=opt+optlen+40*i;s={'name':span(o,8).split(b'\0')[0].decode('ascii'),'virtual_size':u32(o+8),'rva':u32(o+12),'raw_size':u32(o+16),'raw_offset':u32(o+20)}
 span(s['raw_offset'],s['raw_size']);sections.append(s)
def rva(value,n):
 for s in sections:
  delta=value-s['rva']
  if 0<=delta and delta+n<=s['raw_size']:return s['raw_offset']+delta
 raise ValueError('rva_bound')
rr=u32(opt+96+16);rn=u32(opt+96+20);rs=rva(rr,rn);resources=[];seen=set()
def rspan(rel,n):
 if rel<0 or rel+n>rn:raise ValueError('resource_bound')
 return span(rs+rel,n)
def label(v):
 if not v&0x80000000:return v
 rel=v&0x7fffffff;n=struct.unpack('<H',rspan(rel,2))[0]
 if n>256:raise ValueError('resource_name_bound')
 return rspan(rel+2,n*2).decode('utf-16le')
def walk(rel,path):
 if rel in seen or len(path)>3:raise ValueError('resource_cycle_or_depth')
 seen.add(rel);head=rspan(rel,16);named,ids=struct.unpack_from('<HH',head,12);count=named+ids
 if count>1024:raise ValueError('resource_count')
 for i in range(count):
  name,child=struct.unpack('<II',rspan(rel+16+8*i,8));p=path+[label(name)]
  if child&0x80000000:walk(child&0x7fffffff,p)
  else:
   addr,size,cp,reserved=struct.unpack('<IIII',rspan(child,16));off=rva(addr,size);data=span(off,size)
   rec={'path':p,'offset':off,'bytes':size,'sha256':hashlib.sha256(data).hexdigest(),'codepage':cp}
   if len(p)>=2 and p[0]=='JSON':
    rec['json']=json.loads(data.decode('utf-8-sig'))
   elif p[0]==24:rec['xml_text']=data.decode('utf-8-sig')
   resources.append(rec)
walk(0,[])
settings=[r for r in resources if 'SETTINGS.JSON' in r['path']]
strings=[]
for m in re.finditer(rb'[\x20-\x7e]{6,}',b):strings.append((m.start(),m.group().decode('ascii'),'ascii'))
for m in re.finditer(rb'(?:[\x20-\x7e]\0){6,}',b):strings.append((m.start(),m.group().decode('utf-16le'),'utf16le'))
endpoints=[]
for off,text,encoding in strings:
 if ('battle.net' in text or 'battlenet.com.cn' in text) and ('://' in text or text.startswith('.version.')):
  endpoints.append({'offset':off,'encoding':encoding,'text':text,'status':'static_string_not_observed_request','runtime_approved':False})
discovery_names={'/versions','/cdns','cdns_file','fetch_version','Failed to download cdns file','Failed to download versions file','Failed to obtain product config blob file','CDNConfig','BuildConfig','ProductConfig','containerless_ngdp'}
discovery=[{'offset':off,'encoding':enc,'text':text,'runtime_approved':False,'status':'static_component_not_complete_request'} for off,text,enc in strings if text in discovery_names]
imports=[]
# Import names and APIs are evidence of capability, not proof of use or upload.
ir=u32(opt+96+8);iz=u32(opt+96+12);io=rva(ir,iz)
for i in range(min(iz//20,256)):
 o=io+20*i;oft,stamp,fwd,name,ft=struct.unpack('<IIIII',span(o,20))
 if not any((oft,stamp,fwd,name,ft)):break
 no=rva(name,1);dll=span(no,min(256,len(b)-no)).split(b'\0')[0].decode('ascii');apis=[];to=rva(oft or ft,4)
 for j in range(4096):
  v=u32(to+j*4)
  if not v:break
  if v&0x80000000:continue
  a=rva(v+2,1);apis.append(span(a,min(256,len(b)-a)).split(b'\0')[0].decode('ascii'))
 imports.append({'dll':dll,'apis':apis})
certoff=u32(opt+96+32);certsize=u32(opt+96+36);certs=[];wincerts=[];pos=certoff
while certsize and pos<certoff+certsize:
 length,revision,typ=struct.unpack('<IHH',span(pos,8))
 if length<8 or pos+length>certoff+certsize:raise ValueError('certificate_bound')
 wincerts.append({'offset':pos,'length':length,'revision':revision,'type':typ})
 if typ==2:
  der=span(pos+8,length-8)
  if len(der)<2 or der[0]!=0x30:raise ValueError('pkcs7_outer_tag')
  n=der[1]&127
  if der[1]&128:
   if not 1<=n<=4 or len(der)<2+n:raise ValueError('pkcs7_outer_length')
   end=2+n+int.from_bytes(der[2:2+n],'big')
  else:end=2+der[1]
  if end>len(der) or len(der)-end>7 or any(der[end:]):raise ValueError('pkcs7_padding')
  wincerts[-1]['zero_padding_bytes']=len(der)-end
  for c in pkcs7.load_der_pkcs7_certificates(der[:end]):
   certs.append({'subject':c.subject.rfc4514_string(),'issuer':c.issuer.rfc4514_string(),'sha256':c.fingerprint(hashes.SHA256()).hex(),'not_before':c.not_valid_before_utc.isoformat(),'not_after':c.not_valid_after_utc.isoformat()})
 pos+=(length+7)&~7
# Complete generated FileDescriptorProto blobs begin with name field 1.
def varint(data,p):
 value=0
 for i in range(10):
  if p>=len(data):raise ValueError('protobuf_bound')
  c=data[p];p+=1;value|=(c&127)<<(7*i)
  if not c&128:return value,p
 raise ValueError('protobuf_varint_bound')
def descriptor_end(start):
 p=start;limit=min(len(b),start+65536)
 while p<limit:
  last=p;tag,p=varint(b,p);field,wire=tag>>3,tag&7
  if field not in (1,2,3,4,5,6,7,8,9,10,11,12):return last
  if wire==2:
   n,p=varint(b,p)
   if p+n>limit:raise ValueError('protobuf_length_bound')
   p+=n
  elif wire==0:_,p=varint(b,p)
  else:return last
 return p
schemas=[]
def message(m,prefix):
 name=prefix+'.'+m.name
 return [{'name':name,'fields':[{'number':f.number,'name':f.name,'type':f.type,'label':f.label,'type_name':f.type_name} for f in m.field]}]+[r for child in m.nested_type for r in message(child,name)]
for m in re.finditer(rb'\x0a[\x01-\x7f]telemetry_[a-z_]+\.proto',b):
 start=m.start()
 try:
  end=descriptor_end(start);d=descriptor_pb2.FileDescriptorProto();d.ParseFromString(span(start,end-start))
  if not d.name.startswith('telemetry_') or not d.message_type:continue
  schemas.append({'offset':start,'bytes':end-start,'sha256':hashlib.sha256(span(start,end-start)).hexdigest(),'name':d.name,'package':d.package,'messages':[v for child in d.message_type for v in message(child,d.package)],'evidence':'decoded_embedded_schema_not_runtime_value'})
 except Exception:
  # A false-positive byte pattern is not evidence; preserve count separately below.
  continue
interesting_names={'GetVolumeInformationW','GetSystemInfo','GetComputerNameW','RegQueryValueExA','RegQueryValueExW','UuidCreate','UuidToStringA'}
report={'input_sha256':hashlib.sha256(b).hexdigest(),'pe_machine':machine,'pe_format':'PE32','sections':sections,'resources':resources,'settings_resources':settings,'endpoint_strings':endpoints,'download_discovery_strings':discovery,'imported_system_capabilities':[{'dll':r['dll'],'apis':[a for a in r['apis'] if a in interesting_names]} for r in imports if any(a in interesting_names for a in r['apis'])],'imported_network_libraries':[r['dll'] for r in imports if r['dll'].lower() in {'winhttp.dll','wininet.dll','ws2_32.dll'}],'win_certificates':wincerts,'embedded_certificates':certs,'embedded_certificates_are_not_trust_verification':True,'protobuf_descriptors':schemas,'installer_executed':False,'resource_urls_requested':False,'complete_payload_manifest_recovered':False,'catalog_entries_approved':0}
(REPORT/'static-evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'pe_format':report['pe_format'],'resources':len(resources),'endpoint_strings':endpoints,'settings':settings,'protobuf_schemas':[{ 'name':s['name'],'messages':[m['name'] for m in s['messages']]} for s in schemas],'certificates':[c['subject'] for c in certs]},ensure_ascii=False))
