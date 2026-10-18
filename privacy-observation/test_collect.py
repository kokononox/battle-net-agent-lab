import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
s=importlib.util.spec_from_file_location('collect',Path(__file__).with_name('collect.py'));c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
class Tests(unittest.TestCase):
 def test_dns(self):
  self.assertEqual(c.dns_rows(json.dumps([{'Entry':'CDN.Example.COM.','Data':'8.8.8.8'},{'Entry':'private.test','Data':'127.0.0.1'},{'Entry':'bad /token','Data':'8.8.8.8'}]).encode()),{('cdn.example.com','8.8.8.8')})
 def test_dns_cap(self):
  with self.assertRaises(ValueError):c.dns_rows(b' '* (1024*1024+1))
 def test_sampler(self):
  m=c.Sampler(None,{'agent.exe'});raw={'processes':[{'Name':'Agent.exe','ProcessId':9}],'connections':[{'OwningProcess':9,'RemoteAddress':'8.8.8.8','RemotePort':443,'State':'Established'},{'OwningProcess':10,'RemoteAddress':'1.1.1.1','RemotePort':443},{'OwningProcess':9,'RemoteAddress':'192.168.1.1','RemotePort':443}]}
  m.consume(raw,1);m.consume(raw,2)
  self.assertEqual(len(m.endpoints),1);r=next(iter(m.endpoints.values()));self.assertEqual(r['observations'],2);self.assertEqual(r['last_seconds'],2)
 def test_keylog(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'secret';self.assertFalse(c.keylog_summary(p)['file_created'])
   p.write_text('CLIENT_RANDOM '+'a'*64+' '+'b'*96+'\nTOKEN secret\n');r=c.keylog_summary(p)
   self.assertEqual(r['recognized_line_counts'],{'CLIENT_RANDOM':1});self.assertNotIn('bbbb',json.dumps(r));self.assertFalse(r['request_content_observed'])
 def test_endpoint_cap(self):
  m=c.Sampler(None,{'agent.exe'})
  for p in range(1,600):m.consume({'processes':[{'Name':'agent.exe','ProcessId':1}],'connections':[{'OwningProcess':1,'RemoteAddress':'8.8.8.8','RemotePort':p}]},1)
  self.assertEqual(len(m.endpoints),512);self.assertTrue(m.limited)
if __name__=='__main__':unittest.main()
