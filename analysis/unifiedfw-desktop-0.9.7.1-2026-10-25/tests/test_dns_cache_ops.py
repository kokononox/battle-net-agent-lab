import json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
import dns_cache_ops as d,desktop_cli as api
from state import atomic_json
class DnsCacheTests(unittest.TestCase):
 def test_cancel_or_wrong_token_does_not_flush(self):
  for token in ('',None,'RESET WINDOWS HOSTS','flush windows dns cache'):
   with patch.object(d,'require_admin') as a,patch.object(d,'flush_dns') as f,self.assertRaisesRegex(ValueError,'confirmation'):
    d.handle(None,'hosts_reset_dns_flush',dict(confirmation=token),None)
   a.assert_not_called();f.assert_not_called()
 def test_admin_failure_does_not_flush(self):
  with patch.object(d,'require_admin',side_effect=ValueError('admin_required')),patch.object(d,'flush_dns') as f,self.assertRaisesRegex(ValueError,'admin'):
   d.handle(None,'hosts_reset_dns_flush',dict(confirmation=d.CONSENT),None)
  f.assert_not_called()
 def test_only_one_flush_no_store_or_hosts_access(self):
  with patch.object(d,'require_admin') as a,patch.object(d,'flush_dns',return_value=dict(succeeded=True,exit_code=0)) as f:
   r=d.handle(object(),'hosts_reset_dns_flush',dict(confirmation=d.CONSENT),object())
  a.assert_called_once();f.assert_called_once();self.assertTrue(r['dns_cache_flush']['succeeded'])
  for k in ('hosts_changed','firewall_changed','dns_server_settings_changed','trace_sessions_changed'):self.assertFalse(r[k])
 def test_failure_never_claims_hosts_verified(self):
  with patch.object(d,'require_admin'),patch.object(d,'flush_dns',return_value=dict(succeeded=False,error='dns_flush_failed_hosts_already_verified')):
   r=d.handle(None,'hosts_reset_dns_flush',dict(confirmation=d.CONSENT),None)
  self.assertFalse(r['dns_cache_flush']['succeeded']);self.assertNotIn('already_verified',r['dns_cache_flush']['error']);self.assertFalse(r['hosts_changed'])
 def test_nonzero_exit_not_success(self):
  with patch.object(d,'require_admin'),patch.object(d,'flush_dns',return_value=dict(succeeded=False,exit_code=1)):
   self.assertFalse(d.handle(None,'hosts_reset_dns_flush',dict(confirmation=d.CONSENT),None)['dns_cache_flush']['succeeded'])
 def test_unknown_action_not_dispatched(self):
  with patch.object(d,'flush_dns') as f,self.assertRaisesRegex(ValueError,'unknown'):
   d.handle(None,'hosts_reset_apply',dict(confirmation=d.CONSENT),None)
  f.assert_not_called()
 def test_api_routes_cache_before_hosts_reset(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);job=root/'private-state/jobs/a';job.mkdir(parents=True);q=job/'request.json';out=job/'response.json';atomic_json(q,dict(action='hosts_reset_dns_flush',payload=dict(confirmation=d.CONSENT)))
   with patch.object(api,'BASE',root),patch.object(d,'handle',return_value=dict(dns_cache_flush=dict(succeeded=True),hosts_changed=False)) as f:
    self.assertEqual(api.execute(q,out),0)
   f.assert_called_once();r=json.loads(out.read_text());self.assertTrue(r['ok']);self.assertFalse(r['hosts_changed'])
 def test_dns_and_recovery_results_nonmodal(self):
  s=(ROOT/'app/ui-hosts-reset.ps1').read_text('utf-8-sig');result=s[s.index('function Accept-HostsResetResult'):s.index('function Confirm-HostsResetPlan')]
  self.assertNotIn('MessageBox',result);self.assertIn('Accept-DnsFlushResult',result);self.assertIn('$hostsResetHint.Text=$message',result)
