"""Sanitize WinINet API inputs; automatic headers and wire receipt remain unverified."""
import re
from content import TARGETS,HINTS
KNOWN={'host','accept','accept-encoding','accept-language','range','user-agent','connection','content-length','content-type','cookie','authorization','proxy-authorization','cache-control','pragma'}
def classify(p,body=b'',allow_fixture=False):
 server=p.get('server','').lower();fixture=allow_fixture and server=='127.0.0.1'
 if server not in TARGETS and not fixture:return None
 method=p.get('method','').upper();path=p.get('path','');headers=p.get('headers','');names=[]
 for line in headers.split('\r\n'):
  if ':' in line:names.append(line.split(':',1)[0].strip().lower())
 query=path.split('?',1)[1] if '?' in path else '';keys=[x.split('=',1)[0] for x in query.split('&') if x]
 row={'host':server if not fixture else 'synthetic_loopback','method':method if method in {'GET','POST','PUT','PATCH','HEAD','DELETE','OPTIONS'} else 'other',
 'layer':('WinHTTP' if p.get('api_family')=='WinHTTP' else 'WinINet')+'_API_input_not_wire_receipt','port':p.get('port',0),'secure_flag':p.get('secure',False),
 'path_class':'tpr' if path.startswith('/tpr/') else 'version_product' if re.match(r'^/(v[12]/products/)?(agent|bna|bnt)/',path) else 'other',
 'query_present':bool(query),'query_key_count':len(keys),'explicit_header_names':sorted({x if x in KNOWN else '<other>' for x in names}),
 'explicit_credential_header_present':bool({'cookie','authorization','proxy-authorization'}&set(names)),
 'username_argument_present':p.get('username_argument_present',False),'password_argument_present':p.get('password_argument_present',False),
 'body_declared_bytes':p.get('body_declared_bytes',0),'body_observed_bytes':len(body),'body_observed_complete':p.get('body_observed_complete',False),
 'hardware_field_name_hint':bool(HINTS.search(' '.join(names)+' '+' '.join(keys))) or bool(re.search(rb'(?i)(cpu|gpu|hardware|machine|device|fingerprint|serial|uuid|hostname)\s*["\x27]?\s*[:=]',body)),
 'user_agent_argument_present':bool(p.get('agent')),'user_agent_hardware_word_hint':bool(HINTS.search(p.get('agent',''))),
 'api_returned_true':p.get('api_returned_true',False),'error_code':p.get('error',0),
 'automatic_request_headers_observed':False,'send_additional_total_bytes':p.get('additional_total_bytes'), 'api':p.get('api'),'identifier_absence_proven':False}
 return row
