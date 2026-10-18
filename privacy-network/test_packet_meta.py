import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest
from packet_meta import *

def hello(name):
 h=name.encode();ext=b'\x00'+len(h).to_bytes(2,'big')+h;ext=len(ext).to_bytes(2,'big')+ext;ext=b'\x00\x00'+len(ext).to_bytes(2,'big')+ext
 body=b'\x03\x03'+b'x'*32+b'\x00\x00\x02\x13\x01\x01\x00'+len(ext).to_bytes(2,'big')+ext
 hs=b'\x01'+len(body).to_bytes(3,'big')+body
 return b'\x16\x03\x01'+len(hs).to_bytes(2,'big')+hs

def block(kind,b):
 b+=b'\0'*((-len(b))%4);n=12+len(b);return struct.pack('<II',kind,n)+b+struct.pack('<I',n)
def pcap(frame):
 return block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))+block(6,struct.pack('<IIIII',0,0,1,len(frame),len(frame))+frame)
def frame(payload):
 tcp=struct.pack('!HHIIBBHHH',12345,443,50,0,0x50,0x18,1000,0,0)+payload
 ip=b'\x45\x00'+(20+len(tcp)).to_bytes(2,'big')+b'\0\0\0\0\x40\x06\0\0'+ipaddress.ip_address('10.0.0.2').packed+ipaddress.ip_address('8.8.8.8').packed
 return b'\0'*12+b'\x08\x00'+ip+tcp
class PacketTests(unittest.TestCase):
 def test_sni(self):self.assertEqual(client_hello_sni(hello('cdn.example.com')),'cdn.example.com')
 def test_sni_truncated(self):self.assertIsNone(client_hello_sni(hello('cdn.example.com')[:-1]))
 def test_http_sanitized(self):
  r=prefix_metadata(b'POST /path?token=SECRET HTTP/1.1\r\nHost: Example.COM\r\nAuthorization: SECRET\r\n\r\nSECRET')
  self.assertEqual(r['http_host'],'example.com');self.assertEqual(r['http_method'],'POST');self.assertNotIn('SECRET',json.dumps(r))
 def test_host_redaction(self):self.assertEqual(host('abcdef0123456789.example.com'),'redacted.example.com')
 def test_host_reject(self):self.assertIsNone(host('evil.test/?token=secret'))
 def test_prefix_split(self):
  h=hello('cdn.example.com');p=Prefix();p.add(10,h[:30]);p.add(40,h[30:]);self.assertEqual(prefix_metadata(p.data)['tls_sni'],'cdn.example.com')
 def test_prefix_retransmit(self):
  p=Prefix();p.add(10,b'abc');p.add(10,b'abc');p.add(13,b'def');self.assertEqual(p.data,b'abcdef')
 def test_prefix_gap(self):
  p=Prefix();p.add(10,b'abc');p.add(99,b'def');self.assertTrue(p.gap);self.assertEqual(p.data,b'abc')
 def test_dns(self):
  q=b'\x03cdn\x07example\x03com\0';b=struct.pack('!HHHHHH',1,0x8180,1,1,0,0)+q+b'\0\1\0\1'+b'\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4'+b'\x08\x08\x08\x08'
  self.assertIn(('cdn.example.com','8.8.8.8'),dns_answers(b))
 def test_dns_pointer_loop(self):
  with self.assertRaises(ValueError):dns_name(b'\xc0\0',0)
 def test_end_to_end(self):
  with tempfile.TemporaryDirectory() as t:
   f=Path(t)/'capture';f.write_bytes(pcap(frame(hello('cdn.example.com'))));r=analyze(f,{('10.0.0.2',12345,'8.8.8.8',443):{'process_name':'agent.exe','pid':5}})
   self.assertEqual(r['flows'][0]['tls_sni'],'cdn.example.com');self.assertEqual(r['packet_stats']['packets'],1)
 def test_unmatched_not_exported(self):
  with tempfile.TemporaryDirectory() as t:
   f=Path(t)/'capture';f.write_bytes(pcap(frame(hello('private.example.com'))));r=analyze(f,{})
   self.assertEqual(r['flows'],[]);self.assertNotIn('private.example.com',json.dumps(r))
 def test_bad_pcap(self):
  with tempfile.TemporaryDirectory() as t:
   f=Path(t)/'capture';f.write_bytes(b'\0'*8)
   with self.assertRaises(ValueError):list(packets(f,collections.Counter()))
 def test_prefix_cap(self):
  p=Prefix();p.add(0,b'x'*70000);self.assertEqual(len(p.data),65536);self.assertTrue(p.limit)
if __name__=='__main__':unittest.main()
