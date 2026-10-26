"""Bounded response metadata only, never infer privacy from received payload."""
import json
from content import TARGETS

def summarize(p,data):
 if p.get('server','').lower() not in TARGETS:return None
 out={'host':p['server'].lower(),'api':p.get('api'),'observed_bytes':len(data),'layer':('WinHTTP' if p.get('api_family')=='WinHTTP' else 'WinINet')+'_completed_read_API_output','complete_response_proven':False,'body_format':'opaque_or_partial','raw_body_exported':False}
 try:
  text=data.decode('utf-8')
 except UnicodeDecodeError:return out
 if text.startswith('Name!STRING:') or text.startswith('Region!STRING:'):out['body_format']='TACT_table_header_observed'
 else:
  try:
   value=json.loads(text)
   if isinstance(value,dict):out['body_format']='JSON_object_chunk'
   elif isinstance(value,list):out['body_format']='JSON_array_chunk'
  except (ValueError,TypeError):pass
 return out
