import unittest,copy
import research_verdict as v,poststop_content as p
import test_t9_budget as budget
from test_guard_report import rec
import guard_report as g
class Verdict(unittest.TestCase):
 def fixtures(self):
  o=budget.Budget().expanded();guard=g.blank('a'*40,'1');guard['build'].update(stage='compiled',installation_found=True,devcmd_found=True,compiler_exit_code=0);guard.update(status='completed',fixtures={k:rec(k)for k in g.MODES-{'observe'}},observation=o)
  post=p.blank('a'*40,'1');post.update(status='completed',job_drained_verified=True,owned_empty_baseline_verified=True,build_reference_matched=True,official_metadata_materialized=True,hash_checks=1);post['objects']['build_config']=True
  return guard,post
 def test_metadata_not_promoted_to_asset_or_identity(self):
  guard,post=self.fixtures();r=v.assess('a'*40,'1',guard,poststop=post);self.assertTrue(r['official_build_config_materialized']);self.assertFalse(r['official_component_materialized']);self.assertFalse(r['host_related_container_marker_observed']);self.assertFalse(r['file_absence_proven'])
 def test_stale_post_rejected(self):
  guard,post=self.fixtures();post['run_id']='2'
  with self.assertRaises(ValueError):v.assess('a'*40,'1',guard,poststop=post)
 def test_no_post_not_absence(self):
  guard,_=self.fixtures();r=v.assess('a'*40,'1',guard);self.assertIsNone(r['offline_status']);self.assertFalse(r['file_absence_proven'])
 def test_format_hypothesis_never_becomes_observed_flag(self):
  guard,post=self.fixtures();post['prefix_marker']['prediction_bound_before_form_post']=True;post['prefix_marker']['local_hostname_prediction_unchanged']=True;r=v.assess('a'*40,'1',guard,poststop=post);self.assertFalse(r['host_related_container_marker_observed'])
if __name__=='__main__':unittest.main()
