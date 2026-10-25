import copy,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'app'))
from policy import new_config,program_id,blacklist_entry,port_span,port_matches,validate,compile_plan,decision,PolicyError
from state import Store,atomic_json
from workspace_ops import handle
from range_builder import build_range
from monitor_evidence import result_ips,inventory,rule_state
from policy_backups import clean_ui
from risk_confirmations import risks
from isolation_policy import make_policy
import hosts_view
class Fix0981Tests(unittest.TestCase):
 def config(self):
  c=new_config();p=dict(id=program_id('C:/Demo/App.exe'),path='C:\\Demo\\App.exe',sha256='a'*64,enabled=True);c['programs']=[p];return c,p
 def test_compact_full_port_range_one_entry(self):
  p=dict(mode='cidr',value='8.8.8.8',protocol='TCP',port=1,port_end=65535,compact_ports=True)
  from policy import interval
  r=build_range(p,lambda x:interval(x).text(),str);self.assertEqual(len(r['entries']),1);self.assertEqual(r['entries'][0]['port'],'1-65535');self.assertEqual(r['native_rule_upper_bound'],1)
 def test_screenshot_55536_ports_one_rule(self):
  p=dict(mode='cidr',value='8.8.8.8',protocol='UDP',port=10000,port_end=65535,compact_ports=True)
  r=handle(None,'workspace_range_preview',p,None)['range_preview'];self.assertEqual(r['port_count'],55536);self.assertEqual(r['rule_count'],1)
 def test_range_match_boundaries(self):
  c,p=self.config();c['blacklist']=[blacklist_entry([p['id']],'8.8.8.8','TCP','10000-65535')];validate(c)
  for n,blocked in [(9999,False),(10000,True),(65535,True)]:self.assertEqual(decision(c,p['id'],'8.8.8.8',n,'TCP','outside')['outcome']=='block',blocked)
  self.assertEqual(compile_plan(c,'a'*32)['rules'][0]['spec']['port'],'10000-65535')
 def test_invalid_port_ranges_rejected(self):
  for v in [True,False,0,65536,'0-100','10-1','1-65536','1-1','01-10','1-2-3','Any','443']:
   with self.subTest(v=v),self.assertRaises(PolicyError):port_span(v)
 def test_public_mapped_transfer_normalizes(self):
  e=blacklist_entry(['a'*24],'::ffff:8.232.70.12','TCP',443);self.assertEqual(e['target'],'8.232.70.12')
 def test_sink_not_saved_as_external_destination(self):
  for a in ['0.0.0.0','::','::ffff:0:0','127.0.0.1']:
   with self.subTest(a=a),self.assertRaises(PolicyError):blacklist_entry(['a'*24],a,'TCP',443)
 def test_save_roundtrip_native_port_range_with_backup(self):
  with tempfile.TemporaryDirectory() as d:
   store=Store(d);s=store.read();c,p=self.config();s['config']=c;atomic_json(store.file,s)
   row=dict(program_ids=[p['id']],target='::ffff:8.232.70.12',protocol='TCP',port='10000-65535',source_path=p['path'])
   r=handle(store,'workspace_blacklist_save',dict(generation=0,rows=[row]),None)
   self.assertEqual(r['state']['config']['blacklist'][0]['port'],'10000-65535');self.assertEqual(len(list((Path(d)/'policy-backups').glob('*.json'))),1)
 def test_sink_error_is_indexed_and_save_atomic(self):
  with tempfile.TemporaryDirectory() as d:
   store=Store(d);s=store.read();c,p=self.config();s['config']=c;atomic_json(store.file,s);before=store.file.read_bytes()
   rows=[dict(program_ids=[p['id']],target=a,protocol='TCP',port=443,source_path='') for a in ['8.8.8.8','0.0.0.0']]
   with self.assertRaisesRegex(PolicyError,'ردیف 2'):handle(store,'workspace_blacklist_save',dict(generation=0,rows=rows),None)
   self.assertEqual(store.file.read_bytes(),before)
 def test_range_requires_risk_review(self):
  c,p=self.config();c['blacklist']=[blacklist_entry([p['id']],'37.244.29.11','TCP','1-65535')];r=risks(c);self.assertTrue(r['network_ranges']);self.assertTrue(r['known_login_endpoint_entry_ids'])
 def test_backup_preserves_compact_draft(self):
  c,p=self.config();u=dict(ip_rows=[dict(program_ids=[p['id']],target='8.8.8.8',protocol='TCP',port='1-65535',source_path='')],whitelist_text='',mode='blacklist_only');self.assertEqual(clean_ui(u),u)
 def test_mapped_evidence_canonical_raw_unchanged(self):
  raw='::ffff:8.232.70.12;::ffff:0:0;::;0.0.0.0';self.assertEqual(result_ips(raw),['8.232.70.12','0.0.0.0','::']);self.assertIn('ffff',raw)
 def test_actual_hosts_snapshot_not_workspace(self):
  actual=hosts_view.parse_hosts(b'0.0.0.0 a.example\n:: a.example\n')
  with patch.object(hosts_view,'read_windows_hosts',return_value=actual):s=hosts_view.monitor_snapshot()
  self.assertTrue(s['available']);self.assertEqual(s['entries'][0]['mapping_kind'],'local_sink_mapping')
 def test_hosts_unavailable_not_assumed_allow(self):
  with patch.object(hosts_view,'read_windows_hosts',side_effect=OSError('denied')):s=hosts_view.monitor_snapshot()
  self.assertFalse(s['available']);self.assertEqual(s['error'],'denied')
 def test_baseline_and_selected_read_hosts(self):
  for name in ['baseline_ops.py','live_ops.py']:self.assertIn('monitor_snapshot()', (R/'app'/name).read_text())
 def test_white_priority_range_overlap(self):
  c,p=self.config();c.update(mode='full_isolation',whitelist=['8.8.8.8|TCP|443']);c['blacklist']=[blacklist_entry([p['id']],'8.8.8.8','TCP','1-65535')]
  self.assertNotEqual(decision(c,p['id'],'8.8.8.8',443,'TCP','vpn')['outcome'],'block');self.assertEqual(len(make_policy(dict(owner='a'*32,config=c))['overlaps']),1)
if __name__=='__main__':unittest.main()
