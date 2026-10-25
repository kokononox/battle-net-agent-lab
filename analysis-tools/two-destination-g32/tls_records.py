"""Passive TLS record metadata only. Never decrypts, stores or exports payloads."""
import struct
TYPES={20:'change_cipher_spec',21:'alert',22:'handshake',23:'application_data',24:'heartbeat'}
HANDSHAKES={1:'client_hello',2:'server_hello',4:'new_session_ticket',11:'certificate',12:'server_key_exchange',13:'certificate_request',14:'server_hello_done',15:'certificate_verify',16:'client_key_exchange',20:'finished'}
class Direction:
 def __init__(self):
  self.buffer=bytearray();self.handshake=bytearray();self.records=[];self.handshakes=[];self.alerts=[];self.protected=False;self.selected_version='unavailable';self.cipher=None;self.truncated=False;self.invalid=False
 def feed(self,data):
  if self.truncated or self.invalid:return
  # Feed bounded chunks so a huge recv cannot grow the metadata buffer.
  for i in range(0,len(data),4096):
   self.buffer.extend(data[i:i+4096])
   while len(self.buffer)>=5:
    kind,major,minor,n=struct.unpack('!BBBH',self.buffer[:5])
    if major!=3 or minor>4 or n>18432 or kind not in TYPES:self.invalid=True;self.buffer.clear();self.handshake.clear();return
    if len(self.buffer)<5+n:break
    body=bytes(self.buffer[5:5+n]);del self.buffer[:5+n]
    if len(self.records)>=32:self.truncated=True;self.buffer.clear();self.handshake.clear();return
    self.records.append({'type':TYPES[kind],'legacy_version':(major<<8)|minor,'record_bytes':n+5})
    if kind==21 and not self.protected and n==2 and body[0] in {1,2}:self.alerts.append({'level':body[0],'description':body[1]})
    if kind in {20,23}:self.protected=True;self.handshake.clear()
    if kind==22 and not self.protected:self._handshake(body)
 def _handshake(self,body):
  if len(self.handshake)+len(body)>65536:self.truncated=True;self.handshake.clear();return
  self.handshake.extend(body)
  while len(self.handshake)>=4:
   n=int.from_bytes(self.handshake[1:4],'big')
   if n>65532:self.truncated=True;self.handshake.clear();return
   if len(self.handshake)<n+4:return
   kind=self.handshake[0];body=bytes(self.handshake[4:4+n]);del self.handshake[:n+4]
   if len(self.handshakes)<32:self.handshakes.append(HANDSHAKES.get(kind,'other'))
   if kind==2:self._server_hello(body)
 def _server_hello(self,b):
  if len(b)<38:return
  legacy=int.from_bytes(b[:2],'big');session=b[34];pos=35+session
  if pos+3>len(b):return
  cipher=int.from_bytes(b[pos:pos+2],'big');pos+=3;selected=legacy
  if pos<len(b):
   if pos+2>len(b):return
   end=pos+2+int.from_bytes(b[pos:pos+2],'big');pos+=2
   if end!=len(b):return
   while pos<end:
    if pos+4>end:return
    kind,n=struct.unpack('!HH',b[pos:pos+4]);pos+=4
    if pos+n>end:return
    if kind==43 and n==2:selected=int.from_bytes(b[pos:pos+2],'big')
    pos+=n
  self.selected_version={0x301:'tls10',0x302:'tls11',0x303:'tls12',0x304:'tls13'}.get(selected,'other');self.cipher=cipher
 def summary(self):
  return {'records':self.records,'handshake_types':self.handshakes,'cleartext_alerts':self.alerts,'selected_version':self.selected_version,'selected_cipher':self.cipher,'truncated':self.truncated,'invalid_framing':self.invalid,'partial_record_bytes':len(self.buffer),'partial_handshake_bytes':len(self.handshake),'protected_records_seen':self.protected}
class TLSMetadata:
 def __init__(self):self.client=Direction();self.server=Direction()
 def feed(self,direction,data):getattr(self,direction).feed(data)
 def summary(self):return {'scope':'observed_tls_record_headers_not_decrypted','client':self.client.summary(),'server':self.server.summary()}
def validate_summary(v):
 if type(v)!=dict or set(v)!={'scope','client','server'} or v['scope']!='observed_tls_record_headers_not_decrypted':raise ValueError('tls_metadata_schema')
 for name in ('client','server'):
  d=v[name]
  if type(d)!=dict or set(d)!={'records','handshake_types','cleartext_alerts','selected_version','selected_cipher','truncated','invalid_framing','partial_record_bytes','partial_handshake_bytes','protected_records_seen'}:raise ValueError('tls_direction_schema')
  if d['selected_version'] not in {'unavailable','tls10','tls11','tls12','tls13','other'} or not(d['selected_cipher'] is None or type(d['selected_cipher'])==int and 0<=d['selected_cipher']<=65535):raise ValueError('tls_selected')
  for f in ('truncated','invalid_framing','protected_records_seen'):
   if type(d[f])!=bool:raise ValueError('tls_flag')
  for f in ('partial_record_bytes','partial_handshake_bytes'):
   if type(d[f])!=int or not 0<=d[f]<=65536:raise ValueError('tls_partial')
  if type(d['records'])!=list or len(d['records'])>32 or type(d['handshake_types'])!=list or len(d['handshake_types'])>32 or type(d['cleartext_alerts'])!=list or len(d['cleartext_alerts'])>32:raise ValueError('tls_arrays')
  for r in d['records']:
   if type(r)!=dict or set(r)!={'type','legacy_version','record_bytes'} or r['type'] not in TYPES.values() or type(r['legacy_version'])!=int or not 0x300<=r['legacy_version']<=0x304 or type(r['record_bytes'])!=int or not 5<=r['record_bytes']<=18437:raise ValueError('tls_record')
  if any(x not in set(HANDSHAKES.values())|{'other'} for x in d['handshake_types']):raise ValueError('tls_handshake')
  for a in d['cleartext_alerts']:
   if type(a)!=dict or set(a)!={'level','description'} or type(a['level'])!=int or a['level'] not in {1,2} or type(a['description'])!=int or not 0<=a['description']<=255:raise ValueError('tls_alert')
 return v
