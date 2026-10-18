import hashlib,io,json,sys,unittest
from unittest.mock import patch
from preflight import Client,Stop,CAP,config,table,one,key,run
class Response:
 status=200
 def __init__(self,body=b'abc',length='3',status=200,encoding='identity'):self.body=io.BytesIO(body);self.length=length;self.status=status;self.encoding=encoding;self.reads=0
 def getheader(self,k,default=None):return {'Content-Length':self.length,'Content-Encoding':self.encoding}.get(k,default)
 def read(self,n):self.reads+=1;return self.body.read(n)
class Conn:
 def __init__(self,r):self.r=r;self.requests=[];self.closed=False
 def request(self,*a,**kw):self.requests.append((a,kw))
 def getresponse(self):return self.r
 def close(self):self.closed=True
class Tests(unittest.TestCase):
 def fetch(self,r,cap=3,expected=None,used=0):
  c=Client();c.used=used;conn=Conn(r)
  with patch('http.client.HTTPSConnection',return_value=conn):result=c.fetch('https://level3.blizzard.com/tpr/wow/config/ab/cd/abcd',cap,expected)
  return c,conn,result
 def test_existing_receipt_no_restart(self):
  with patch('pathlib.Path.exists',return_value=True),patch('http.client.HTTPSConnection') as conn,self.assertRaises(Stop):run()
  conn.assert_not_called()
 def test_exact(self):
  c,conn,b=self.fetch(Response());self.assertEqual(b,b'abc');self.assertEqual(c.used,3);self.assertTrue(conn.closed);self.assertEqual(conn.requests[0][0][0],'GET')
 def test_no_redirect(self):
  r=Response(status=302)
  with self.assertRaises(Stop):self.fetch(r)
  self.assertEqual(r.reads,0)
 def test_oversize_before_body(self):
  r=Response(length='4')
  with self.assertRaises(Stop):self.fetch(r)
  self.assertEqual(r.reads,0)
 def test_total_no_reset(self):
  r=Response()
  with self.assertRaises(Stop):self.fetch(r,used=CAP-2)
  self.assertEqual(r.reads,0)
 def test_exact_size_mismatch(self):
  with self.assertRaises(Stop):self.fetch(Response(),expected=2)
 def test_missing_length(self):
  with self.assertRaises(Stop):self.fetch(Response(length=None))
 def test_compression_rejected(self):
  with self.assertRaises(Stop):self.fetch(Response(encoding='gzip'))
 def test_truncated_counted(self):
  c=Client();conn=Conn(Response(body=b'a'))
  with patch('http.client.HTTPSConnection',return_value=conn),self.assertRaises(Stop):c.fetch('https://level3.blizzard.com/tpr/wow/config/a',3)
  self.assertEqual(c.used,1)
 def test_host_rejected(self):
  for url in ('https://evil.test/x','http://level3.blizzard.com/x','https://level3.blizzard.com/x?y=1','https://level3.blizzard.com/../x'):
   with self.assertRaises(Stop):Client().fetch(url,3)
 def test_config_identity(self):
  b=b'build-name = fixture\n';self.assertEqual(config(b,hashlib.md5(b).hexdigest())['build-name'],'fixture')
  with self.assertRaises(Stop):config(b,'0'*32)
 def test_duplicate_config(self):
  b=b'x = 1\nx = 2\n'
  with self.assertRaises(Stop):config(b,hashlib.md5(b).hexdigest())
 def test_table_and_region(self):
  rows=table(b'Region!STRING:0|BuildId!DEC:4\neu|1\nus|2\n');self.assertEqual(one(rows,'Region','eu')['BuildId'],'1')
  with self.assertRaises(Stop):one(rows+rows,'Region','eu')
 def test_invalid_hash(self):
  with self.assertRaises(Stop):key('../bad')
 def test_deadline(self):
  c=Client();c.started-=601
  with self.assertRaises(Stop):c.fetch('https://level3.blizzard.com/x',3)
if __name__=='__main__':unittest.main()
