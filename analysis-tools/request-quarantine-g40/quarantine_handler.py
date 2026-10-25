"""Quarantine-only Windows loopback HTTP endpoint: native admission first.
No upstream connection or forwarding route; local 403 only. Not a live proxy
replacement until system gate/recovery and product controller are integrated.
"""
import re,socketserver,threading
import domain_proxy as protocol
import quarantine as q
CAPACITY=threading.BoundedSemaphore(8)
class QuarantineOnlyHandler(socketserver.BaseRequestHandler):
 def handle(self):
  permit=None
  if not CAPACITY.acquire(False):return
  try:
   self.request.settimeout(5)
   permit=protocol.admit(self.request,self.server.peer_policy)
   permit.revalidate()
   request,fields=protocol.header(self.request)
   if any(k=='transfer-encoding' for k,v in fields):raise ValueError('unsupported_body')
   lengths=[v for k,v in fields if k=='content-length']
   if len(lengths)>1 or lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>8):raise ValueError('unsupported_body')
   length=int(lengths[0]) if lengths else 0
   if length>q.MAX_BODY:raise ValueError('unsupported_body')
   permit.revalidate()
   body=protocol.exact(self.request,length)
   raw=(' '.join(request)+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in fields)+'\r\n').encode('iso-8859-1')+body
   permit.revalidate()
   receipt=self.server.quarantine_gate.inspect_http(raw)
   self.server.receipts.append(receipt.public())
  except Exception:
   self.server.receipts.append(q.Receipt(reason='quarantine_unavailable').public())
  finally:
   # Reply only to loopback peer, never to a content server.
   try:self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
   except OSError:pass
   if permit is not None:permit.close()
   CAPACITY.release()
class LoopbackServer(socketserver.ThreadingTCPServer):
 allow_reuse_address=False;daemon_threads=True
 def __init__(self,address,gate,peer_policy):
  if address[0]!='127.0.0.1':raise ValueError('loopback_only')
  super().__init__(address,QuarantineOnlyHandler)
  self.quarantine_gate=gate;self.peer_policy=peer_policy;self.receipts=[]
