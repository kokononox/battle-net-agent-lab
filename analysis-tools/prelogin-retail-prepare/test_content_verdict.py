import unittest
import content_verdict as v,content_probe as c,guard_report as g
import test_t9_budget as budget_fixture
class Verdict(unittest.TestCase):
 def gate(self):
  o=budget_fixture.Budget().expanded();r=g.blank('a'*40,'1');r['observation']=o;r['build'].update(stage='compiled',installation_found=True,devcmd_found=True,compiler_exit_code=0)
  from test_guard_report import rec
  for mode in g.MODES-{'observe'}:r['fixtures'][mode]=rec(mode)
  r.update(status='completed');return r
 def test_completed_without_content_does_not_prove_game(self):
  r=v.assess('a'*40,'1',self.gate());self.assertFalse(r['official_component_materialized']);self.assertFalse(r['same_file_socket_delivery_proven']);self.assertFalse(r['game_file_absence_after_stop_proven'])
 def test_stale_rejected_even_when_looks_positive(self):
  content=c.blank('a'*40,'2')
  with self.assertRaises(ValueError):v.assess('a'*40,'1',self.gate(),content=content)
 def test_stopped_not_mistaken_for_absence(self):
  gate=self.gate();gate['observation'].update(status='phase_network_limit',root_exit_code=125);gate.update(status='refused',error_kind='native_failed')
  r=v.assess('a'*40,'1',gate);self.assertEqual(r['status'],'stopped_before_content_proof');self.assertFalse(r['game_file_absence_after_stop_proven'])
if __name__=='__main__':unittest.main()
