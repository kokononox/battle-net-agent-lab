import sys,types,unittest,ssl,tempfile,socket,threading
from pathlib import Path
from unittest.mock import patch
# Isolated protocol tests, never used by the packed production executable.
fake=types.ModuleType('peer_guard');fake.admit=lambda *a:None;sys.modules['peer_guard']=fake
import domain_proxy as d
class Permit:
 def revalidate(self):pass
 def close(self):pass
class Policy(unittest.TestCase):
 def hello(self,name):
  incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();obj=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname=name)
  try:obj.do_handshake()
  except ssl.SSLWantReadError:pass
  return outgoing.read()[5:]
 def test_exact_authority(self):
  for h in d.HOSTS:self.assertEqual(d.authority(h+':80',80),h)
 def test_lookalikes_denied(self):
  for h in ['level3.ssl.blizzard.com','level3.blizzard.com.example.org','us.version.battle.net@other','127.0.0.1','us.version.battle.net:443','us.version.battle.net/']:
   with self.subTest(h=h),self.assertRaises(ValueError):d.authority(h,80)
 def test_sni(self):
  for h in d.HOSTS:self.assertEqual(d.sni(self.hello(h)),h)
 def test_other_sni(self):
  with self.assertRaises(ValueError):d.sni(self.hello('example.com'))
 def test_bad_tls(self):
  h=self.hello('us.version.battle.net')
  for v in [b'',b'bad',h[:30],b'\x02'+h[1:]]:
   with self.assertRaises(ValueError):d.sni(v)
 def test_nonpublic_pins(self):
  c=dict(hosts={h:['1.1.1.1'] for h in d.HOSTS},port=18731,seconds=60,log='x',peer_policy='x')
  d.validated_config(c);c['hosts']['level3.blizzard.com']=['127.0.0.1']
  with self.assertRaises(ValueError):d.validated_config(c)
 def test_no_dial_unknown_peer_and_host(self):
  class Stream:
   def __init__(self,b):self.b=b;self.sent=b''
   def recv(self,n):v=self.b[:n];self.b=self.b[n:];return v
   def sendall(self,b):self.sent+=b
   def settimeout(self,n):pass
  with tempfile.TemporaryDirectory() as tmp:
   cfg=dict(log=str(Path(tmp)/'log'),peer_policy='x');srv=types.SimpleNamespace(config=cfg,transparent_http=True,destination_port=1119)
   for peer,host in [(False,'us.version.battle.net:1119'),(True,'example.com:1119'),(True,'level3.blizzard.com:1119')]:
    req=Stream(('GET /agent/versions HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode())
    with patch.object(d,'admit',side_effect=(lambda *a:Permit()) if peer else ValueError('peer_not_in_owned_job')),patch.object(d,'connect') as connect:
     d.Handler(req,('127.0.0.1',12345),srv);connect.assert_not_called();self.assertTrue(req.sent.startswith(b'HTTP/1.1 403'))
 def test_http_forward_and_metadata(self):
  with tempfile.TemporaryDirectory() as tmp:
   up=socket.socket();up.bind(('127.0.0.1',0));up.listen();wire=[]
   def remote():
    c,_=up.accept()
    with c:
     v=b''
     while b'\r\n\r\n' not in v:v+=c.recv(4096)
     wire.append(v);c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
   t=threading.Thread(target=remote);t.start();cfg=dict(log=str(Path(tmp)/'log'),peer_policy='x')
   with d.Server(('127.0.0.1',0),d.Handler) as server:
    server.config=cfg;server.transparent_http=True;server.destination_port=1119
    with patch.object(d,'admit',return_value=Permit()),patch.object(d,'connect',side_effect=lambda *a:socket.create_connection(up.getsockname())):
     worker=threading.Thread(target=server.handle_request);worker.start()
     with socket.create_connection(server.server_address) as c:
      c.sendall(b'GET /agent/versions?private=secret HTTP/1.1\r\nHost: us.version.battle.net:1119\r\n\r\n')
      while c.recv(4096):pass
     worker.join(5);t.join(5)
   up.close();text=Path(cfg['log']).read_text();self.assertNotIn('secret',text);self.assertIn('"status": 200',text);self.assertIn(b'Host: us.version.battle.net:1119',wire[0])
if __name__=='__main__':unittest.main()
