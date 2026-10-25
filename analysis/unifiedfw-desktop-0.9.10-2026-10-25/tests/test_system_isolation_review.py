import copy,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch,Mock
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from policy import new_config,validate,decision,blacklist_entry,program_id,PolicyError
from isolation_policy import make_policy
from policy_backups import clean_ui as validate_ui
from state import Store
import isolation_ops,policy_review

class SystemIsolationReviewTests(unittest.TestCase):
 def state(self,mode='direct_isolation'):
  c=new_config();c.update(mode=mode,whitelist=['8.8.8.8|TCP|443-445']);return dict(owner='a'*32,config=c)
 def test_direct_policy_whole_system(self):
  p=make_policy(self.state());self.assertEqual(p['connection'],'direct');self.assertEqual(p['scope'],'whole_system');self.assertNotIn('rules',p);self.assertFalse(p['no_leak_certified'])
 def test_vpn_policy_stays_vpn(self):self.assertEqual(make_policy(self.state('full_isolation'))['connection'],'vpn')
 def test_legacy_not_silently_native(self):
  with self.assertRaises(PolicyError):make_policy(self.state('vpn_allowlist'))
 def test_global_direct_applies_to_unregistered_process(self):
  c=self.state()['config']
  for interface in ['outside','unknown','vpn']:
   self.assertNotEqual(decision(c,'unregistered','8.8.8.8',443,'TCP',interface)['outcome'],'block')
   self.assertEqual(decision(c,'unregistered','1.1.1.1',443,'TCP',interface)['outcome'],'block')
 def test_global_vpn_unregistered_still_no_direct(self):
  c=self.state('full_isolation')['config'];self.assertEqual(decision(c,'unregistered','8.8.8.8',443,'TCP','outside')['outcome'],'block');self.assertNotEqual(decision(c,'unregistered','8.8.8.8',443,'TCP','vpn')['outcome'],'block')
 def test_direct_precise_protocol_and_port(self):
  c=self.state()['config']
  for proto,port in [('TCP',442),('TCP',446),('UDP',443)]:self.assertEqual(decision(c,'unregistered','8.8.8.8',port,proto,'outside')['outcome'],'block')
 def test_direct_whitelist_priority(self):
  s=self.state();c=s['config'];path='C:\\App.exe';p=dict(id=program_id(path),path=path,sha256='b'*64,enabled=True);c['programs']=[p];c['blacklist']=[blacklist_entry([p['id']],'8.8.8.8','TCP','1-65535')];review=policy_review.build_review(s)
  self.assertEqual(len(review['overlaps']),1);self.assertTrue(any(x['severity']=='notice' for x in review['issues']));self.assertNotEqual(decision(c,p['id'],'8.8.8.8',443,'TCP','outside')['outcome'],'block');self.assertEqual(decision(c,p['id'],'8.8.8.8',446,'TCP','outside')['outcome'],'block')
 def test_validate_direct_and_backup_draft(self):
  validate(self.state()['config']);v=dict(ip_rows=[],whitelist_text='8.8.8.8|TCP|443',mode='direct_isolation');self.assertEqual(validate_ui(v),v)
 def test_backup_and_save_roundtrip(self):
  with tempfile.TemporaryDirectory() as d:
   store=Store(pathlib.Path(d)/'state');s=store.read();store.configure('direct_isolation',['8.8.8.8|TCP|443'],0);self.assertEqual(store.read()['config']['mode'],'direct_isolation');self.assertEqual(store.read()['owner'],s['owner']);self.assertTrue(list((store.root/'policy-backups').glob('*.json')))
 def test_direct_empty_not_permitted(self):
  s=self.state();s['config']['whitelist']=[]
  with self.assertRaises(PolicyError):make_policy(s)
 def test_old_mode_review_is_not_ready(self):
  r=policy_review.build_review(self.state('vpn_allowlist'));self.assertTrue(any(x['severity']=='error' for x in r['issues']));self.assertEqual(r['native_readiness'],'not_checked')
 def test_review_read_only_off_windows(self):
  store=Mock();store.read.return_value=self.state()
  with patch.object(policy_review,'is_windows',return_value=False),patch.object(isolation_ops,'native') as native:
   r=policy_review.handle(store,{},None)['policy_review'];native.assert_not_called();self.assertFalse(r['applied']);self.assertFalse(r['firewall_changed']);self.assertEqual(r['native_readiness'],'unknown')
 def test_review_only_native_prepare(self):
  store=Mock();store.read.return_value=self.state();answer=dict(isolation_plan=dict(review=dict(quarantine_allow_count=5)))
  with patch.object(policy_review,'is_windows',return_value=True),patch.object(isolation_ops,'handle',return_value=answer) as native:
   r=policy_review.handle(store,{},None)['policy_review'];self.assertEqual(native.call_args.args[1],'isolation_prepare');self.assertEqual(r['native_readiness'],'ready_at_check_time');self.assertFalse(r['applied']);self.assertEqual(r['quarantine_allow_count'],5)
 def test_review_translates_native_failure(self):
  store=Mock();store.read.return_value=self.state('full_isolation')
  with patch.object(policy_review,'is_windows',return_value=True),patch.object(isolation_ops,'handle',side_effect=PolicyError('iso_exactly_one_connected_full_tunnel_SSTP_required; no_firewall_mutation')):
   result=policy_review.handle(store,{},None);r=result['policy_review'];self.assertEqual(r['native_readiness'],'blocked');self.assertTrue(any(x['title']=='VPN مناسب پیدا نشد' for x in r['issues']));self.assertNotIn('iso_exactly',json.dumps(r,ensure_ascii=False));self.assertIn('iso_exactly',result['technical']['preflight_error'])
 def test_review_no_legacy_compile_blockers(self):
  r=policy_review.build_review(self.state());text=json.dumps(r);self.assertNotIn('disconnect_monitor_not_implemented',text);self.assertNotIn('production_firewall_activation_not_enabled',text)
 def test_unknown_error_is_not_success(self):
  row=policy_review.explain_error('unrecognized_traceback_token');self.assertEqual(row['severity'],'error');self.assertNotIn('unrecognized_traceback_token',str(row))
 def test_blacklist_review_does_not_prepare_isolation(self):
  s=self.state('blacklist_only');s['config']['whitelist']=[];store=Mock();store.read.return_value=s
  with patch.object(isolation_ops,'handle') as native:r=policy_review.handle(store,{},None);native.assert_not_called();self.assertFalse(r['policy_review']['applied'])
 def test_direct_does_not_add_auto_dns_or_dhcp(self):
  p=make_policy(self.state());self.assertEqual(len(p['whitelist']),1);self.assertEqual(p['whitelist'][0]['remote_port'],'443-445');self.assertIn('no_automatic_DNS_DHCP',p['outside_tunnel'])

if __name__=='__main__':unittest.main()
