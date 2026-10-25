import json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from binary_observer import BinaryObserver
from signature_observation import result,decode_response
class Observe(unittest.TestCase):
 def test_signature_protocol(self):
  def payload(status=0,publisher=True):return json.dumps(dict(trust_status=status,expected_blizzard_publisher=publisher)).encode()
  self.assertEqual(decode_response(0,payload())['status'],'accepted')
  self.assertEqual(decode_response(0,payload(-1,False))['status'],'trust_rejected')
  self.assertEqual(decode_response(0,payload(0,False))['status'],'publisher_rejected')
  self.assertEqual(decode_response(0,payload(-1,True))['status'],'output_rejected')
  self.assertEqual(decode_response(0,payload(True,True))['status'],'output_rejected')
  self.assertEqual(decode_response(0,b'{"trust_status":0,"trust_status":0,"expected_blizzard_publisher":true}')['status'],'output_rejected')
  self.assertEqual(decode_response(0,b'X'*4097)['status'],'output_limit')
  self.assertEqual(decode_response(3221225477,b'private text not exported'),result('helper_failed',-1073741819))
 def test_no_probe_before_stability(self):
  verify=Mock(return_value=result('accepted',0,0));observer=BinaryObserver(verify,lambda p:('2.1.0.1','accepted'));obs=SimpleNamespace(is_reparse=lambda p:False)
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'fake.exe';path.write_bytes(b'MZ'+b'X'*32)
   for t in (0,9):self.assertIsNone(observer.sample(path,'client',obs,{},t)[0])
   verify.assert_not_called();b,p=observer.sample(path,'client',obs,{},11);self.assertTrue(b['signature_accepted']);self.assertEqual(verify.call_count,1)
   path.write_bytes(b'MZ'+b'Y'*32);self.assertIsNone(observer.sample(path,'client',obs,{},30)[0]);self.assertEqual(verify.call_count,1)
 def test_helper_failure_never_accepts(self):
  verify=Mock(side_effect=[result('helper_failed',-1),result('accepted',0,0)]);observer=BinaryObserver(verify,lambda p:('2.1.0.1','accepted'));obs=SimpleNamespace(is_reparse=lambda p:False)
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'fake.exe';path.write_bytes(b'MZ'+b'X'*32);observer.sample(path,'client',obs,{},0)
   b,p=observer.sample(path,'client',obs,{},11);self.assertFalse(b['signature_accepted']);self.assertEqual(p['status'],'helper_failed')
   b,p=observer.sample(path,'client',obs,{},27);self.assertTrue(b['signature_accepted']);self.assertEqual(p['status'],'accepted')
 def test_changed_during_probe_never_accepts(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'fake.exe';path.write_bytes(b'MZ'+b'X'*32)
   def verify(p,env):p.write_bytes(b'MZ'+b'Y'*32);return result('accepted',0,0)
   observer=BinaryObserver(verify,lambda p:('2.1.0.1','accepted'));obs=SimpleNamespace(is_reparse=lambda p:False);observer.sample(path,'client',obs,{},0)
   b,p=observer.sample(path,'client',obs,{},11);self.assertIsNone(b);self.assertEqual(p['status'],'file_changed')
 def test_busy_file_is_not_accepted(self):
  observer=BinaryObserver(Mock(),Mock());obs=SimpleNamespace(is_reparse=lambda p:False)
  b,p=observer.sample(Path('/not/a/real/file.exe'),'client',obs,{},0);self.assertIsNone(b);self.assertEqual(p['status'],'file_busy')
 def test_persistent_helper_failure_budget(self):
  from run_case import footprint
  from model import blank
  class LabError(Exception):pass
  obs=SimpleNamespace(is_reparse=lambda p:False,LabError=LabError)
  r=blank({'BNET_REPLICA':'r1'});observer=BinaryObserver(lambda p,e:result('helper_failed',-1),lambda p:('2.1.0.1','accepted'))
  registry=lambda root:(dict(registry_key_found=True,registry_location_match=True,registry_version_present=False),'missing')
  with tempfile.TemporaryDirectory() as d,patch('run_case.registry_checks',side_effect=registry):
   root=Path(d)
   for name in ('Battle.net Launcher.exe','Battle.net.exe'):(root/name).write_bytes(b'MZ'+b'X'*32)
   for elapsed in (0,15,30):
    with patch('run_case.time.monotonic',return_value=elapsed):
     checks,binaries,_,_=footprint(root,obs,{},observer,r,elapsed);self.assertFalse(checks['version_evidence_verified'])
   with patch('run_case.time.monotonic',return_value=45),self.assertRaisesRegex(LabError,'retry_budget_exhausted'):footprint(root,obs,{},observer,r,45)
   self.assertEqual(r['binary_probe_counts']['helper_failed'],6)
   self.assertTrue(all(not b['signature_accepted'] for b in binaries))
