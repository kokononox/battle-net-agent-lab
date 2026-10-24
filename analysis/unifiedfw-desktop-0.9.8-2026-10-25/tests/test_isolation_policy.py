import copy,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from policy import new_config,program_id,blacklist_entry,whitelist_spec,whitelist_text,decision,PolicyError,validate
from isolation_policy import make_policy
from state import Store
import isolation_ops
import workspace_ops

class IsolationPolicyTests(unittest.TestCase):
 def state(self,white=None):
  c=new_config();c.update(mode='full_isolation',whitelist=['8.8.8.8|TCP|443-445'] if white is None else white)
  pid=program_id('C:/Demo/A.exe');c['programs']=[dict(id=pid,path='C:\\Demo\\A.exe',sha256='a'*64,enabled=True)]
  c['blacklist']=[blacklist_entry([pid],'8.8.8.8','TCP',443)]
  return dict(schema='unified-firewall-state-1',owner='a'*32,config=c)
 def test_legacy_all_protocols_preserved(self):
  s=whitelist_spec('8.8.8.0/24');self.assertEqual(s['protocol'],'Any');self.assertEqual(s['port'],0)
 def test_tcp_range_canonical(self):
  self.assertEqual(whitelist_text(whitelist_spec('8.8.8.8|TCP|443-445')),'8.8.8.8|TCP|443-445')
 def test_udp_range(self):self.assertEqual(whitelist_spec('8.8.8.8|UDP|53')['port_end'],53)
 def test_any_wildcard(self):self.assertEqual(whitelist_spec('8.8.8.8|ANY|*')['protocol'],'Any')
 def test_invalid_transport_rejected(self):
  for v in ['8.8.8.8|ICMP|1','8.8.8.8|TCP|0','8.8.8.8|TCP|65536','8.8.8.8|UDP|60-53','8.8.8.8|Any|443','example.com|TCP|443','8.8.8.8|TCP|*']:
   with self.subTest(v=v),self.assertRaises(PolicyError):whitelist_spec(v)
 def test_no_owned_black_rule_in_allow_only_native_policy(self):
  p=make_policy(self.state());self.assertNotIn('blacklist',p);self.assertNotIn('rules',p);self.assertEqual(p['whitelist'][0]['remote_port'],'443-445')
 def test_overlap_report(self):self.assertEqual(len(make_policy(self.state())['overlaps']),1)
 def test_udp_mismatch_not_overlap(self):self.assertEqual(make_policy(self.state(['8.8.8.8|UDP|443']))['overlaps'],[])
 def test_port_mismatch_not_overlap(self):self.assertEqual(make_policy(self.state(['8.8.8.8|TCP|444']))['overlaps'],[])
 def test_no_false_no_leak_claim(self):self.assertFalse(make_policy(self.state())['no_leak_certified'])
 def test_native_requires_full_isolation(self):
  s=self.state();s['config']['mode']='vpn_allowlist'
  with self.assertRaises(PolicyError):make_policy(s)
 def test_native_rejects_empty(self):
  with self.assertRaises(PolicyError):make_policy(self.state([]))
 def test_precise_priority_model(self):
  s=self.state();c=s['config'];pid=c['programs'][0]['id']
  self.assertNotEqual(decision(c,pid,'8.8.8.8',443,'TCP','vpn')['outcome'],'block')
  for iface in ['outside','unknown']:
   self.assertEqual(decision(c,pid,'8.8.8.8',443,'TCP',iface)['outcome'],'block')
  for proto,port in [('UDP',443),('TCP',446),('TCP',442)]:self.assertEqual(decision(c,pid,'8.8.8.8',port,proto,'vpn')['outcome'],'block')
 def test_blacklist_only_never_uses_white_exemption(self):
  s=self.state();c=s['config'];c['mode']='blacklist_only';pid=c['programs'][0]['id'];self.assertEqual(decision(c,pid,'8.8.8.8',443,'TCP','vpn')['outcome'],'block')
 def test_ipv6(self):self.assertEqual(make_policy(self.state(['2606:4700::/32|UDP|53']))['whitelist'][0]['remote_addresses'],['2606:4700::/32'])
 def test_wildcard_white_range_preview_not_saved(self):
  r=workspace_ops.handle(None,'workspace_whitelist_range_preview',dict(mode='pattern',value='8.8.8.*',last='',protocol='TCP',port=4000,port_end=5000),None)
  p=r['whitelist_range_preview'];self.assertFalse(p['saved']);self.assertFalse(p['applied']);self.assertEqual(int(p['address_count']),256);self.assertTrue(p['rules'][0].endswith('|TCP|4000-5000'))
 def test_any_explicit_zero(self):
  with self.assertRaises(PolicyError):workspace_ops.handle(None,'workspace_whitelist_range_preview',dict(mode='cidr',value='8.8.8.8',protocol='Any',port=1,port_end=1),None)
 def test_full_port_range_is_not_65535_entries(self):
  r=workspace_ops.handle(None,'workspace_whitelist_range_preview',dict(mode='cidr',value='8.8.8.0/24',protocol='UDP',port=1,port_end=65535),None)
  self.assertEqual(len(r['whitelist_range_preview']['rules']),1)
 def test_isolation_linux_refuses_native(self):
  with self.assertRaises(PolicyError):isolation_ops.native('Apply',{},Path('/invalid'))
 def test_no_consent_never_calls_worker(self):
  with tempfile.TemporaryDirectory() as d:
   store=Store(d)
   with patch('isolation_ops.native') as n:
    with self.assertRaises(PolicyError):isolation_ops.handle(store,'isolation_restore',{},Path(d))
    n.assert_not_called()
 def test_native_call_never_uses_subprocess_timeout(self):
  import inspect
  text=inspect.getsource(isolation_ops.native);self.assertNotIn('timeout=',text);self.assertNotIn('.kill(',text)
 def test_desktop_mutation_errors_not_no_change(self):
  text=(Path(__file__).resolve().parents[1]/'app/desktop_cli.py').read_text();self.assertIn("'isolation_apply','isolation_restore'",text)
 def test_native_disallows_old_blacklist_engine(self):
  text=(Path(__file__).resolve().parents[1]/'app/isolation-native.ps1').read_text('utf-8-sig');self.assertIn('iso_restore_native_blacklist_first',text)
 def test_protected_task_not_portable_user_code(self):
  text=(Path(__file__).resolve().parents[1]/'app/isolation-worker.ps1').read_text('utf-8-sig');self.assertIn("Join-Path $script:IsoRoot 'isolation-worker.ps1'",text);self.assertIn("-UserId 'SYSTEM'",text)
if __name__=='__main__':unittest.main()
