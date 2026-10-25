import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from hosts_experiment import HostsExperiment,null_answers,for_runner,resolve_override
import os
from experiment_policy import hosts_blank,POLICIES
from model import validate
class Hosts(unittest.TestCase):
 def test_resolver_child_protocol_without_network(self):
  env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','TEMP','TMP'}}
  self.assertTrue(resolve_override('0.0.0.0',env))
 def test_null_answers(self):
  self.assertTrue(null_answers(['0.0.0.0','::','::ffff:0:0']))
  for values in ([],['8.8.8.8'],['0.0.0.0','8.8.8.8'],['127.0.0.1'],['bad']):self.assertFalse(null_answers(values))
 def test_control_never_reads_or_writes_hosts(self):
  r=hosts_blank('r1');original=r.copy();flush=Mock();resolve=Mock();exp=HostsExperiment('/not/used', '/not/used',r,{},flush,resolve)
  exp.apply();self.assertTrue(exp.check());self.assertTrue(exp.restore());self.assertEqual(r,original);flush.assert_not_called();resolve.assert_not_called()
 def test_backup_exact_mapping_and_restore(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'hosts';original=b'# original\r\n127.0.0.1 localhost\r\n';path.write_bytes(original);r=hosts_blank('r3');exp=HostsExperiment(path,d,r,{},lambda e:0,lambda domain,e:domain=='telemetry-in.battle.net')
   exp.apply();self.assertEqual((Path(d)/'hosts-before.bak').read_bytes(),original);self.assertTrue(r['resolver_verified']);self.assertIn(b'0.0.0.0 telemetry-in.battle.net',path.read_bytes());self.assertTrue(exp.check());self.assertTrue(exp.restore());self.assertEqual(path.read_bytes(),original);self.assertTrue(r['restored'])
 def test_detect_override_changed(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'hosts';path.write_bytes(b'# before');r=hosts_blank('r5');exp=HostsExperiment(path,d,r,{},lambda e:0,lambda domain,e:True);exp.apply();path.write_bytes(b'# unrelated change');self.assertFalse(exp.check());self.assertFalse(exp.restore());self.assertEqual(path.read_bytes(),b'# unrelated change');self.assertEqual(r['verification_failures'],1)
 def test_mapping_failure_stops_before_target(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'hosts';original=b'# before';path.write_bytes(original);r=hosts_blank('r6');exp=HostsExperiment(path,d,r,{},lambda e:0,lambda domain,e:False)
   with self.assertRaisesRegex(ValueError,'override_verification_failed'):exp.apply()
   self.assertFalse(r['resolver_verified']);self.assertTrue(exp.restore());self.assertEqual(path.read_bytes(),original)
 def test_flush_failure_is_not_valid_override(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'hosts';path.write_bytes(b'# before');r=hosts_blank('r3');exp=HostsExperiment(path,d,r,{},lambda e:1,lambda domain,e:True)
   with self.assertRaisesRegex(ValueError,'dns_flush_failed'):exp.apply()
   self.assertFalse(r['resolver_verified'])
 def test_nonhosted_factory_refused_before_os_access(self):
  with patch.dict('os.environ',{},clear=True),self.assertRaisesRegex(ValueError,'approved_hosted_case_required'):for_runner('/unused',hosts_blank('r3'),{},None)
 def test_unknown_domain_refused(self):
  r=hosts_blank('r3');r['domain']='example.com'
  with self.assertRaisesRegex(ValueError,'not_approved'):HostsExperiment('/unused','/unused',r,{})
 def test_report_case_and_hosts_crossfoot(self):
  from test_model import Gates
  r=Gates().success('r3');validate(r);r['hosts']['resolver_verified']=False
  with self.assertRaises(ValueError):validate(r)
  r=Gates().success('r1');r['hosts']['override_written']=True
  with self.assertRaises(ValueError):validate(r)
 def test_same_install_gate_all_six(self):
  from test_model import Gates
  for key in POLICIES:
   with self.subTest(replica=key):validate(Gates().success(key))
