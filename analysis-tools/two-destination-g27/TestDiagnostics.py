import json,socket,tempfile,types,unittest,sys
from pathlib import Path
from unittest.mock import patch
fake=types.ModuleType('peer_guard');fake.admit=lambda *a:None;sys.modules['peer_guard']=fake
import domain_proxy as d
class Permit:
 def __init__(self,fail=False):self.fail=fail;self.calls=0
 def revalidate(self):
  self.calls+=1
  if self.fail:raise ValueError('peer_owner_missing')
 def close(self):pass
class Sender:
 def __init__(self,results):self.results=iter(results)
 def send(self,data):
  n=next(self.results)
  if isinstance(n,Exception):raise n
  return n
class Tests(unittest.TestCase):
 def test_partial_send_counted(self):
  t=d.new_transfer();p=Permit();d.send_counted(Sender([2,3]),b'abcde',p,t,'client')
  self.assertEqual(t['client_sent_bytes'],5);self.assertEqual(t['client_attempted_bytes'],8);self.assertEqual(p.calls,2)
 def test_revoked_peer_no_send(self):
  t=d.new_transfer();dest=Sender([])
  with self.assertRaisesRegex(ValueError,'peer_owner_missing'):d.send_counted(dest,b'x',Permit(True),t,'client')
  self.assertEqual(t['client_sent_bytes'],0);self.assertEqual(t['client_attempted_bytes'],0)
 def test_error_preserves_confirmed_prefix(self):
  t=d.new_transfer()
  with self.assertRaises(BrokenPipeError):d.send_counted(Sender([2,BrokenPipeError()]),b'abcde',Permit(),t,'tls_hello')
  self.assertEqual(t['tls_hello_sent_bytes'],2);self.assertTrue(t['send_error_partial_possible'])
 def test_zero_send_refused(self):
  with self.assertRaisesRegex(ValueError,'socket_send_no_progress'):d.send_counted(Sender([0]),b'a',Permit(),d.new_transfer(),'client')
 def test_tls_failure_final_metadata(self):
  class Stream:
   def settimeout(self,*a):pass
   def close(self):pass
  with tempfile.TemporaryDirectory() as tmp:
   cfg={'log':str(Path(tmp)/'events'),'peer_policy':'x'}
   with patch.object(d,'admit',return_value=Permit()),patch.object(d,'clienthello',return_value=(b'hello','us.version.battle.net')),patch.object(d,'connect',side_effect=ValueError('peer_owner_missing')):
    d.TransparentTLSHandler(Stream(),('127.0.0.1',1),types.SimpleNamespace(config=cfg))
   rows=[json.loads(x) for x in Path(cfg['log']).read_text().splitlines()];final=[x for x in rows if x['kind']=='tls_transfer_final']
   self.assertEqual(len(final),1);self.assertEqual(final[0]['tls_hello_read_bytes'],5);self.assertEqual(final[0]['tls_hello_sent_bytes'],0);self.assertEqual(final[0]['end_reason'],'peer_owner_missing')
 def test_failure_before_admission_final(self):
  with tempfile.TemporaryDirectory() as tmp:
   cfg={'log':str(Path(tmp)/'events'),'peer_policy':'x'}
   with patch.object(d,'admit',side_effect=ValueError('peer_not_in_owned_job')),patch.object(d,'connect') as connect:
    d.TransparentTLSHandler(object(),('127.0.0.1',1),types.SimpleNamespace(config=cfg));connect.assert_not_called()
   rows=[json.loads(x) for x in Path(cfg['log']).read_text().splitlines()];self.assertEqual(rows[-1]['end_reason'],'peer_not_in_owned_job')
 def test_eof_direction(self):
  a,aa=socket.socketpair();b,bb=socket.socketpair()
  with a,aa,b,bb:
   aa.close();t=d.new_transfer();d.relay(a,b,Permit(),{},'us.version.battle.net',t);self.assertEqual(t['end_reason'],'client_eof')
 def test_permit_before_server_forward(self):
  a,aa=socket.socketpair();b,bb=socket.socketpair()
  with a,aa,b,bb:
   bb.sendall(b'server data');t=d.new_transfer()
   with self.assertRaisesRegex(ValueError,'peer_owner_missing'):d.relay(a,b,Permit(True),{},'us.version.battle.net',t)
   self.assertEqual(t['server_read_bytes'],11);self.assertEqual(t['server_sent_bytes'],0)
 def test_sanitizer_rejects_raw_fields(self):
  with tempfile.TemporaryDirectory() as tmp:
   cfg={'log':str(Path(tmp)/'events')};d.metadata(cfg,'tls_transfer_final','example.net',body='SECRET',end_reason='raw secret!',server_sent_bytes=-1)
   t=Path(cfg['log']).read_text();self.assertNotIn('SECRET',t);self.assertNotIn('raw secret',t);self.assertNotIn('server_sent_bytes',t)
if __name__=='__main__':unittest.main()
