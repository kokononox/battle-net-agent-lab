"""Local reference matching; values never returned in public results."""
import re,zlib,urllib.parse

def references():
 import winreg
 result={}
 targets=[(r'HARDWARE\DESCRIPTION\System\CentralProcessor\0','ProcessorNameString','cpu_model'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','BIOSVersion','bios_version'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','BIOSVendor','bios_vendor'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','BIOSReleaseDate','bios_release_date'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','SystemManufacturer','system_manufacturer'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','SystemProductName','system_model'),
 (r'HARDWARE\DESCRIPTION\System\BIOS','BaseBoardProduct','board_model')]
 for path,name,category in targets:
  try:
   with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path) as k:v=winreg.QueryValueEx(k,name)[0]
   vals=v if isinstance(v,list) else [v]
   good=[x.strip() for x in vals if isinstance(x,str) and 4<=len(x.strip())<=160 and x.strip().lower() not in {'default string','to be filled by o.e.m.','unknown','system product name','system manufacturer'}]
   if good:result[category]=good
  except OSError:pass
 return result

def literal_matches(request,refs):
 import base64
 target=request['target'];headers=request['headers'];body=base64.b64decode(request['body_sample_base64'])
 head=(request['method']+' '+target+' HTTP/1.1\r\n'+'\r\n'.join(k+': '+v for k,v in headers)+'\r\n\r\n').encode('latin1')
 samples=[head+body,urllib.parse.unquote_to_bytes((head+body).replace(b'+',b' '))]
 enc=dict(headers).get('content-encoding','').lower()
 if enc in {'gzip','deflate'}:
  try:
   decoded=zlib.decompressobj(31 if enc=='gzip' else 15).decompress(body,65536)
   samples.extend([decoded,urllib.parse.unquote_to_bytes(decoded.replace(b'+',b' '))])
  except zlib.error:pass
 matches=[]
 for category,values in refs.items():
  if any(v.encode(codec) in sample for v in values for codec in ('utf-8','utf-16-le') for sample in samples):matches.append(category)
 return sorted(matches)
