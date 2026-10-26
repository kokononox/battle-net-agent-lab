"""Local-only physical upstream receipt control. No installer, external HTTP or TLS.

This harness is deliberately NOT a proxy implementation. feed/finish are called
by a trusted in-process adapter. Only canonical admitted bytes go to a loopback
sink; unknown input never invokes socket.create_connection.
"""
import os,json,socket,socketserver,threading
from pathlib import Path
from pre_send_gate import CompleteRequestGate,load_policy,CDN_HOST,VERSION_HOST
from download_path_audit import load_reference,full_object_size

class Sink:
 def __init__(self):
  self.receipts=[];self.accepts=0;self.done=threading.Event();owner=self
  class Handler(socketserver.BaseRequestHandler):
   def handle(self):
    owner.accepts+=1;self.request.settimeout(2);parts=[];total=0
    try:
     while True:
      b=self.request.recv(4096)
      if not b:break
      total+=len(b)
      if total>16384:raise RuntimeError('fixture_receipt_cap')
      parts.append(b)
     owner.receipts.append(b''.join(parts))
    finally:owner.done.set()
  self.server=socketserver.TCPServer(('127.0.0.1',0),Handler)
  self.port=self.server.server_address[1]
  self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True)
 def __enter__(self):self.thread.start();return self
 def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(3)

class LoopbackFixtureRelay:
 def __init__(self,port):
  if type(port) is not int or not 1<=port<=65535:raise ValueError('fixture_port')
  self.port=port;self.connection_attempts=0
 def send(self,decision):
  if not decision.allowed:return False
  if decision.host not in (CDN_HOST,VERSION_HOST) or not decision.wire:raise ValueError('fixture_admission')
  self.connection_attempts+=1
  # Immutable literal loopback, never the client-supplied Host or any URL.
  with socket.create_connection(('127.0.0.1',self.port),timeout=2) as conn:
   conn.sendall(decision.wire)
  return True

def run(base):
 base=Path(base);policy=load_policy(base);refs,_=load_reference(base)
 path=next(p for p in sorted(refs) if full_object_size(p,refs) is not None and not refs.ranges.get(p) and full_object_size(p,refs)>1)
 size=full_object_size(path,refs);route='/v2/products/agent/versions'
 def req(p=path,host=CDN_HOST,headers=b'',body=b''):
  return ('GET '+p+' HTTP/1.1\r\nHost: '+host+'\r\n').encode()+headers+b'\r\n'+body
 def expected(p=path,host=CDN_HOST,ran=None):
  return ('GET '+p+' HTTP/1.1\r\nHost: '+host+'\r\nAccept: */*\r\nConnection: close\r\n'+('Range: '+ran+'\r\n' if ran else '')+'\r\n').encode()
 full='bytes=0-'+str(size-1);valid=req(headers=('Range: '+full+'\r\n').encode())
 cases=[
  ('public_CDN_single',[req()],expected()),
  ('public_CDN_fragmented_full_range',[bytes([b]) for b in valid],expected(ran=full)),
  ('public_metadata',[req(route,VERSION_HOST)],expected(route,VERSION_HOST)),
  ('query_identifier',[req(path+'?id=PRIVATE_SENTINEL')],None),
  ('user_agent_identifier',[req(headers=b'User-Agent: PRIVATE_SENTINEL\r\n')],None),
  ('cookie_identifier',[req(headers=b'Cookie: PRIVATE_SENTINEL\r\n')],None),
  ('authorization_identifier',[req(headers=b'Authorization: PRIVATE_SENTINEL\r\n')],None),
  ('body_identifier',[req(body=b'PRIVATE_SENTINEL')],None),
  ('unknown_header',[req(headers=b'X-Device: PRIVATE_SENTINEL\r\n')],None),
  ('range_one_byte_short',[req(headers=('Range: bytes=0-'+str(size-2)+'\r\n').encode())],None),
  ('unknown_destination',[req(host='PRIVATE_SENTINEL.invalid')],None),
  ('pipelined_tail',[req(),req(path+'?id=PRIVATE_SENTINEL')],None),
  ('late_fragment_body',[req(),b'PRIVATE_SENTINEL'],None),
  ('incomplete_headers',[req()[:-1]],None),
  ('opaque_TLS_bytes',[b'\x16\x03\x03\x00\x10PRIVATE_SENTINEL'],None),
  ('duplicate_host',[req(headers=('Host: '+CDN_HOST+'\r\n').encode())],None),
  ('transfer_encoding',[req(headers=b'Transfer-Encoding: chunked\r\n')],None),
 ]
 rows=[]
 for label,chunks,want in cases:
  with Sink() as sink:
   gate=CompleteRequestGate(policy);relay=LoopbackFixtureRelay(sink.port)
   for chunk in chunks:gate.feed(chunk)
   # No relay is called during partial input. Evidence checks pre-release counts.
   before=relay.connection_attempts==sink.accepts==0 and sink.receipts==[]
   decision=gate.finish();sent=relay.send(decision)
   if want is not None:
    completed=sink.done.wait(3)
    passed=before and decision.allowed and sent and completed and relay.connection_attempts==1 and sink.accepts==1 and sink.receipts==[want]
   else:
    passed=before and not decision.allowed and not sent and relay.connection_attempts==sink.accepts==0 and sink.receipts==[]
   rows.append({'case':label,'passed':passed,'expected_allowed':want is not None,
                'no_upstream_connection_before_complete_admission':before,
                'upstream_connection_attempts':relay.connection_attempts,
                'upstream_accepted_connections':sink.accepts,
                'upstream_receipt_exact_canonical_request':sink.receipts==[want] if want is not None else None,
                'denied_zero_upstream_connections_and_bytes':relay.connection_attempts==sink.accepts==0 and not sink.receipts if want is None else None,
                'decision':decision.audit()})
 return {'schema':'g74-complete-request-pre-send-fixture-1','run_id':os.environ.get('GITHUB_RUN_ID','local'),
         'source_commit':os.environ.get('GITHUB_SHA','local'),'passed':all(r['passed'] for r in rows),
         'rows':rows,'case_count':len(rows),'external_service_used':False,'loopback_sink_only':True,
         'installer_started':False,'firewall_changed':False,'certificate_trust_changed':False,
         'transparent_proxy_implemented':False,'production_integration_complete':False,
         'all_outbound_paths_covered':False,'raw_values_exported':False,'fingerprinting_absence_proven':False}
if __name__=='__main__':
 result=run(Path(__file__).parent);out=Path('output');out.mkdir(exist_ok=True)
 (out/'g74-pre-send-fixture.json').write_text(json.dumps(result,indent=2))
 print('G74_FIXTURE='+json.dumps(result))
 raise SystemExit(0 if result['passed'] else 1)
