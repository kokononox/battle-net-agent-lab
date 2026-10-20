"""Local in-memory buffer analysis. Never return raw body, header or field value."""
import json
import re
import urllib.parse
import zlib

FIELD_ALIASES={
 'bios':'bios','biosversion':'bios_version','biosvendor':'bios_vendor','biosreleasedate':'bios_release_date','serialnumber':'serial_number','systemserialnumber':'system_serial_number','baseboard':'baseboard','motherboard':'motherboard','systemmanufacturer':'system_manufacturer','systemproductname':'system_model',
 'cpu':'cpu','cpumodel':'cpu_model','cpuname':'cpu_name','cpuinfo':'cpu_info','processor':'processor',
 'gpu':'gpu','gpumodel':'gpu_model','gpuname':'gpu_name','videocard':'video_card','memory':'memory','ram':'ram','totalmemory':'total_memory','systemmemory':'system_memory',
 'os':'os','osversion':'os_version','operatingsystem':'operating_system','deviceid':'device_id','hardwareid':'hardware_id','machineid':'machine_id','installationid':'installation_id','installid':'install_id','clientid':'client_id','locale':'locale','platform':'platform','screenresolution':'screen_resolution','architecture':'architecture','systeminfo':'system_info'}
METHODS={'GET','POST','PUT','HEAD','OPTIONS','CONNECT','DELETE','PATCH'}
FORMATS={'empty','unreadable','json','form_like','http_headers_only','gzip_incomplete','deflate_incomplete','other_or_binary'}

def analyze_body(data,declared,readable=True):
 result={'format':'empty' if declared==0 else 'other_or_binary','compression':'none','decoded_truncated':False,'field_name_hints':[],'keys_examined':0,'http_host':None,'http_method':None}
 if not readable:result['format']='unreadable';return result
 if not data:return result
 body=data;encoding=None
 if re.match(rb'^(GET|POST|PUT|HEAD|OPTIONS|CONNECT|DELETE|PATCH) [^\r\n]{1,4096} HTTP/1\.[01]\r\n',data):
  if b'\r\n\r\n' not in data:return result
  header,body=data.split(b'\r\n\r\n',1)
  result['http_method']=header.split(b' ',1)[0].decode('ascii')
  for line in header.split(b'\r\n')[1:]:
   key,sep,value=line.partition(b':')
   if key.lower()==b'host':
    try:result['http_host']=value.strip().decode('ascii').split(':',1)[0]
    except UnicodeError:pass
   elif key.lower()==b'content-encoding':encoding=value.strip().lower()
  if not body:result['format']='http_headers_only';return result
 if body.startswith(b'\x1f\x8b') or encoding==b'gzip':
  result['compression']='gzip';mode=31
 elif encoding==b'deflate':result['compression']='deflate';mode=15
 else:mode=None
 if mode is not None:
  try:
   z=zlib.decompressobj(mode);body=z.decompress(body,65536);result['decoded_truncated']=not z.eof
   if not z.eof:result['format']=result['compression']+'_incomplete';return result
  except zlib.error:result['format']=result['compression']+'_incomplete';return result
 try:text=body.decode('utf-8')
 except UnicodeError:return result
 matches=set();seen=0
 def key(name):
  nonlocal seen
  if seen>=512:return
  seen+=1;alias=FIELD_ALIASES.get(re.sub('[^a-z0-9]','',str(name).lower()))
  if alias:matches.add(alias)
 def walk(obj,depth=0):
  if depth>8 or seen>=512:return
  if isinstance(obj,dict):
   for k,v in obj.items():key(k);walk(v,depth+1)
  elif isinstance(obj,list):
   for v in obj[:512]:walk(v,depth+1)
 try:
  obj=json.loads(text);walk(obj);result['format']='json'
 except (ValueError,RecursionError):
  if len(text)<=65536 and re.fullmatch(r'[A-Za-z0-9_.%+\-]+=[^\r\n]*',text):
   result['format']='form_like'
   for part in text.split('&')[:512]:key(urllib.parse.unquote_plus(part.partition('=')[0]))
 result['field_name_hints']=sorted(matches);result['keys_examined']=seen
 return result
