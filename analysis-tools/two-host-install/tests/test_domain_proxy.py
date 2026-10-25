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
