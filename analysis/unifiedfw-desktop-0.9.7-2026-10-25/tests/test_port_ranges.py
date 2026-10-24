import pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from range_builder import build_range
from policy import interval

def preview(**kw):
 q=dict(mode='cidr',value='8.8.8.8/32',port=1000,port_end=1002,protocol='TCP');q.update(kw)
 return build_range(q,lambda x:(interval(x) and x),lambda es:'\n'.join(str(e) for e in es))
class PortRangeTests(unittest.TestCase):
 def test_inclusive_endpoints(self):self.assertEqual([e['port'] for e in preview()['entries']],[1000,1001,1002])
 def test_unchanged_engine_representation(self):self.assertTrue(all(type(e['port']) is int for e in preview()['entries']))
 def test_no_implicit_UDP(self):self.assertEqual({e['protocol'] for e in preview()['entries']},{'TCP'})
 def test_explicit_UDP(self):self.assertEqual({e['protocol'] for e in preview(protocol='UDP')['entries']},{'UDP'})
 def test_single_port_backwards_compatible(self):p=preview(port=443,port_end=443);self.assertEqual((p['rule_count'],p['port_count']),(1,1))
 def test_missing_end_keeps_single(self):
  q=dict(mode='cidr',value='8.8.8.8',port=443,protocol='TCP');p=build_range(q,lambda x:(interval(x) and x),str);self.assertEqual(p['port_last'],443)
 def test_high_port_boundary(self):self.assertEqual(preview(port=65534,port_end=65535)['entries'][-1]['port'],65535)
 def test_zero_rejected(self):
  with self.assertRaises(ValueError):preview(port=0)
 def test_out_of_range_rejected(self):
  with self.assertRaises(ValueError):preview(port_end=65536)
 def test_reverse_range_rejected(self):
  with self.assertRaises(ValueError):preview(port=1002,port_end=1000)
 def test_bool_not_port(self):
  with self.assertRaises(ValueError):preview(port=True)
 def test_string_not_end(self):
  with self.assertRaises(ValueError):preview(port_end='1002')
 def test_256_exact_boundary(self):self.assertEqual(preview(port=1,port_end=256)['rule_count'],256)
 def test_257_no_partial_or_truncation(self):
  with self.assertRaisesRegex(ValueError,'no_partial_expansion'):preview(port=1,port_end=257)
 def test_all_ports_rejected_explicitly_not_silently_any(self):
  with self.assertRaisesRegex(ValueError,'total_cap=256'):preview(port=1,port_end=65535)
 def test_existing_draft_budget(self):
  with self.assertRaisesRegex(ValueError,'remaining=2'):preview(row_budget=2)
 def test_zero_remaining_budget(self):
  with self.assertRaisesRegex(ValueError,'remaining=0'):preview(row_budget=0)
 def test_native_rule_limit(self):
  with self.assertRaisesRegex(ValueError,'native_1024'):preview(port=1,port_end=33,program_count=32)
 def test_explicit_list_not_entire_span(self):
  p=preview(mode='targets',value='8.8.8.8\n1.1.1.1');self.assertEqual(len(p['entries']),6);self.assertEqual({e['ip'] for e in p['entries']},{'8.8.8.8','1.1.1.1'});self.assertTrue(p['destination_set_not_contiguous']);self.assertEqual(p['address_count'],'2')
 def test_duplicate_IP_not_duplicate_rule(self):self.assertEqual(preview(mode='targets',value='8.8.8.8\n8.8.8.8')['rule_count'],3)
 def test_list_public_IPv6(self):p=preview(mode='targets',value='2606:4700:4700::1111\n8.8.8.8');self.assertEqual(p['ip_rule_count'],2)
 def test_list_does_not_resolve_domain(self):
  with self.assertRaises(ValueError):preview(mode='targets',value='example.com')
 def test_list_rejects_CIDR_use_separate_mode(self):
  with self.assertRaises(ValueError):preview(mode='targets',value='8.8.8.0/24')
 def test_list_private_rejected_by_existing_validator(self):
  with self.assertRaises(ValueError):preview(mode='targets',value='10.0.0.1')
 def test_range_network_cross_product(self):
  p=preview(mode='between',value='8.8.8.8',last='8.8.8.12');self.assertEqual(p['rule_count'],p['ip_rule_count']*3);self.assertEqual(p['native_rule_upper_bound'],p['rule_count'])
 def test_no_network_changes(self):self.assertFalse(preview()['applied'])
 def test_GUI_explicit_preview_and_observed_binding(self):
  s=(ROOT/'app/ui-workspace.ps1').read_text(encoding='utf-8-sig');self.assertIn('port_end=[int]$endPort.Value',s);self.assertIn('range_source_path',s);self.assertIn('row_budget=',s);self.assertIn('no',preview()['port_range_representation'])

class PortRangePolicyIntegrationTests(unittest.TestCase):
 def setUp(self):
  import tempfile
  from state import Store
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
  self.store=Store(self.root/'private',lambda p:dict(path=str(p),sha256='a'*64));self.store.read()
  self.s=self.store.register([r'C:\Games\Wow.exe',r'C:\Other\Wow.exe'],0);self.pid=self.s['config']['programs'][0]['id']
 def tearDown(self):self.tmp.cleanup()
 def save(self,source=r'C:\Games\Wow.exe'):
  import workspace_ops as w
  p=preview();rows=[dict(program_ids=[self.pid],target=e['ip'],protocol=e['protocol'],port=e['port'],source_path=source) for e in p['entries']]
  return w.handle(self.store,'workspace_blacklist_save',dict(generation=1,rows=rows),self.root)
 def test_range_saves_only_config_then_compiles_exact_ports(self):
  from policy import compile_plan
  v=self.save();self.assertTrue(v['saved_only']);self.assertFalse(v['firewall_changed']);c=v['state']['config'];plan=compile_plan(c,v['state']['owner'])
  self.assertEqual(len(plan['rules']),3);self.assertEqual({r['spec']['port'] for r in plan['rules']},{1000,1001,1002});self.assertTrue(all(r['spec']['program']==r'C:\Games\Wow.exe' for r in plan['rules']))
 def test_expanded_rows_keep_exact_observed_binding(self):
  from policy import PolicyError
  before=self.store.file.read_bytes()
  with self.assertRaisesRegex(PolicyError,'observed_EXE'):self.save(r'C:\Other\Wow.exe')
  self.assertEqual(before,self.store.file.read_bytes())
 def test_saved_range_only_hits_requested_protocol_and_ports(self):
  from policy import decision
  c=self.save()['state']['config']
  self.assertEqual(decision(c,self.pid,'8.8.8.8',1001,'TCP','outside')['outcome'],'block')
  self.assertNotEqual(decision(c,self.pid,'8.8.8.8',999,'TCP','outside')['outcome'],'block')
  self.assertNotEqual(decision(c,self.pid,'8.8.8.8',1001,'UDP','outside')['outcome'],'block')
