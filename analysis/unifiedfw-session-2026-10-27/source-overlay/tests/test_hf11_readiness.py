import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'app'))
from hf11_readiness import summarize
from policy_review import explain_error
class HF11ReadinessTests(unittest.TestCase):
 def result(self,mode='direct_isolation',ready='ready_at_check_time',issues=None):
  return {'policy_review':{'mode':mode,'native_readiness':ready,'issues':issues or []},'technical':{}}
 def test_ready_is_not_applied(self):
  r=summarize(self.result());self.assertTrue(r['preflight_passed']);self.assertFalse(r['applied']);self.assertFalse(r['no_leak_certified'])
 def test_legacy_or_blacklist_not_isolation_ready(self):
  for mode in ['blacklist_only','vpn_allowlist']:self.assertFalse(summarize(self.result(mode=mode))['preflight_passed'])
 def test_errors_override_ready(self):
  self.assertFalse(summarize(self.result(issues=[{'severity':'error','title':'x'}]))['preflight_passed'])
 def test_unknown_or_blocked_not_ready(self):
  for state in ['unknown','blocked','not_checked']:self.assertFalse(summarize(self.result(ready=state))['preflight_passed'])
 def test_sanitized_output(self):
  s=self.result();s['policy_review']['whitelist']=['private-ip'];s['policy_review']['issues']=[{'severity':'warning','title':'a','fix':'b','detail':'private-path'}];s['technical']['preflight_error']='C:\\private\\user: value'
  text=str(summarize(s));self.assertNotIn('private-ip',text);self.assertNotIn('private-path',text);self.assertNotIn('C:\\private',text)
 def test_new_errors_are_user_facing(self):
  for code in ['iso_firewall_interface_exclusion_detected','iso_interface_exclusions_unreadable','iso_profile_identity']:
   r=explain_error(code);self.assertEqual(r['severity'],'error');self.assertNotEqual(r['title'],'آمادگی اعمال تأیید نشد')
