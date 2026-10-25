import pathlib,ssl,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from domain_proxy import *
class Policy(unittest.TestCase):
 def hello(self,name):
  incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();obj=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname=name)
  try:obj.do_handshake()
  except ssl.SSLWantReadError:pass
  data=outgoing.read();return data[5:]
 def test_real_clienthello(self):
  for host in HOSTS:self.assertEqual(sni(self.hello(host)),host)
 def test_other_sni_refused(self):
  with self.assertRaises(ValueError):sni(self.hello('example.com'))
 def test_exact_hosts_only(self):
  self.assertEqual(authority('level3.blizzard.com:80',80),'level3.blizzard.com')
  for text in ['level3.ssl.blizzard.com','level3.blizzard.com.example.org','us.version.battle.net@other','127.0.0.1','us.version.battle.net:443','us.version.battle.net/']:
   with self.subTest(text=text),self.assertRaises(ValueError):authority(text,80)
 def test_config_nonpublic_refused(self):
  c=dict(hosts={h:['1.1.1.1'] for h in HOSTS},port=18731,seconds=60,log='private.jsonl');validated_config(c);c['hosts']['level3.blizzard.com']=['127.0.0.1']
  with self.assertRaises(ValueError):validated_config(c)
 def test_missing_sni_and_bad_lengths_refused(self):
  good=self.hello('us.version.battle.net')
  for b in [b'',b'bad',good[:30],b'\x02'+good[1:]]:
   with self.assertRaises(ValueError):sni(b)

class Transparency(unittest.TestCase):
 def test_fragmented_tls_record_reader(self):
  hello=Policy().hello('us.version.battle.net');record=b'\x16\x03\x01'+len(hello).to_bytes(2,'big')+hello
  class Stream:
   def __init__(self,b):self.b=b
   def recv(self,n):out=self.b[:min(n,3)];self.b=self.b[len(out):];return out
  raw,name=clienthello(Stream(record));self.assertEqual(raw,record);self.assertEqual(name,'us.version.battle.net')
 def test_fragmented_handshake_across_records(self):
  hello=Policy().hello('level3.blizzard.com');parts=[hello[:7],hello[7:]];record=b''.join(b'\x16\x03\x01'+len(b).to_bytes(2,'big')+b for b in parts)
  class Stream:
   def __init__(self,b):self.b=b
   def recv(self,n):out=self.b[:n];self.b=self.b[n:];return out
  raw,name=clienthello(Stream(record));self.assertEqual(name,'level3.blizzard.com')
 def test_transparent_http_keeps_host_and_path(self):
  import socket,threading,tempfile
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   upstream=socket.socket();upstream.bind(('127.0.0.1',0));upstream.listen();observed=[]
   def remote():
    c,_=upstream.accept()
    with c:
     data=b''
     while b'\r\n\r\n' not in data:data+=c.recv(4096)
     observed.append(data);c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
   t=threading.Thread(target=remote);t.start()
   cfg=dict(hosts={h:['1.1.1.1'] for h in HOSTS},port=18731,seconds=30,log=str(pathlib.Path(d)/'log.jsonl'),transparent=True);validated_config(cfg)
   with Server(('127.0.0.1',0),Handler) as server:
    server.config=cfg;server.transparent_http=True;server.daemon_threads=False
    with patch('domain_proxy.connect',side_effect=lambda *args:socket.create_connection(upstream.getsockname())):
     worker=threading.Thread(target=server.handle_request);worker.start()
     with socket.create_connection(server.server_address) as c:
      c.sendall(b'GET /bnet/versions?sample=1 HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n');response=c.recv(4096)
     worker.join(3);t.join(3)
   upstream.close();self.assertTrue(response.startswith(b'HTTP/1.1 200'));self.assertIn(b'GET /bnet/versions?sample=1 ',observed[0]);self.assertIn(b'Host: us.version.battle.net',observed[0])
   logtext=(pathlib.Path(d)/'log.jsonl').read_text();self.assertNotIn('sample=1',logtext)

class VersionPort(unittest.TestCase):
 def test_exact_host_port_forwarding(self):
  import tempfile,types
  from unittest.mock import patch
  class Stream:
   def __init__(self,b):self.b=b;self.sent=bytearray()
   def recv(self,n):out=self.b[:n];self.b=self.b[n:];return out
   def sendall(self,b):self.sent.extend(b)
   def settimeout(self,n):pass
   def close(self):pass
  with tempfile.TemporaryDirectory() as d:
   cfg=dict(log=str(pathlib.Path(d)/'private.jsonl'))
   srv=types.SimpleNamespace(config=cfg,transparent_http=True,destination_port=1119)
   up=Stream(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
   req=Stream(b'GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net:1119\r\n\r\n')
   with patch('domain_proxy.connect',return_value=up) as c:
    Handler(req,('127.0.0.1',12345),srv)
   c.assert_called_once_with(cfg,'us.version.battle.net',1119)
   self.assertIn(b'Host: us.version.battle.net:1119\r\n',up.sent)
   self.assertTrue(req.sent.startswith(b'HTTP/1.1 200'))
   for name in ['level3.blizzard.com:1119','example.com:1119','us.version.battle.net:80']:
    req=Stream(('GET /agent/versions HTTP/1.1\r\nHost: '+name+'\r\n\r\n').encode())
    with patch('domain_proxy.connect') as c:Handler(req,('127.0.0.1',12345),srv)
    c.assert_not_called();self.assertTrue(req.sent.startswith(b'HTTP/1.1 403'))
