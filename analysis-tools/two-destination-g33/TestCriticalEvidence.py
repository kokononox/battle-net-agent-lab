import copy,unittest
import CriticalEvidence as c
SHA='a'*40;RUN='123'
def report():return {'source_commit':SHA,'run_id':RUN,'scenario':'real_setup','status':'two_host_bootstrap_observed_restore_refused','driver':{'post_restore_canary_connected':None},'recovery':{'restore_refused':True,'firewall_restored':False,'registration_changes':3},'completion_evidence':{'assessment':{'package_installation_verified':True,'complete_installation_verified':False,'main_process_survival_60s_observed':True}}}
def text(r=None):return '\n'.join(c.lines(r or report())[1])
class Tests(unittest.TestCase):
 def test_roundtrip(self):self.assertEqual(c.extract(text(),SHA,RUN)[1],c.build(report()))
 def test_refusal_not_success(self):d=c.extract(text(),SHA,RUN)[1];self.assertTrue(d['recovery']['restore_refused']);self.assertFalse(d['recovery']['firewall_restored'])
 def test_package_not_full_readiness(self):d=c.build(report());self.assertTrue(d['assessment']['package_installation_verified']);self.assertFalse(d['assessment']['complete_installation_verified']);self.assertFalse(d['installation_verified'])
 def test_no_post_restore_canary_fabricated(self):self.assertIsNone(c.build(report())['driver']['post_restore_canary_connected'])
 def test_wrong_source(self):
  with self.assertRaises(ValueError):c.extract(text(),'b'*40,RUN)
 def test_wrong_run(self):
  with self.assertRaises(ValueError):c.extract(text(),SHA,'456')
 def test_missing_part(self):
  with self.assertRaises(ValueError):c.extract('\n'.join(text().splitlines()[:-1]),SHA,RUN)
 def test_duplicate_part(self):
  with self.assertRaises(ValueError):c.extract(text()+'\n'+text().splitlines()[-1],SHA,RUN)
 def test_corrupt_payload(self):
  s=text().splitlines();s[-1]=s[-1][:-1]+'!'
  with self.assertRaises(ValueError):c.extract('\n'.join(s),SHA,RUN)
 def test_unknown_field(self):
  d=c.build(report());d['raw_path']='secret'
  with self.assertRaises(ValueError):c.validate(d,SHA,RUN)
 def test_raw_string_rejected(self):
  d=c.build(report());d['status']='https://example.org/?secret=x'
  with self.assertRaises(ValueError):c.validate(d,SHA,RUN)
 def test_private_source_fields_omitted(self):
  r=report();r['raw_command']='secret';self.assertNotIn('secret',text(r))
 def test_partial_later_preserves_last_complete(self):self.assertEqual(c.extract(text()+'\nG33_CORE_MANIFEST {"parts":2}',SHA,RUN)[1],c.build(report()))
 def test_head_and_tail_both_complete(self):
  block=text();large='\n'.join('noncritical '+str(i) for i in range(500));combined=block+'\n'+large+'\n'+block
  self.assertEqual(c.extract('\n'.join(combined.splitlines()[:25]),SHA,RUN)[1],c.build(report()));self.assertEqual(c.extract('\n'.join(combined.splitlines()[-25:]),SHA,RUN)[1],c.build(report()))
 def test_summarized_diff_bound(self):
  r=report();r['registration_differences']=[{'identifier':'Task'+str(i)} for i in range(20)];d=c.build(r);self.assertEqual(len(d['registration_differences']),8);self.assertEqual(d['registration_differences_omitted'],12)
if __name__=='__main__':unittest.main()
