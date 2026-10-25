import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from language_poll import Poll,keep

def no_target():return dict(status='no_targets',helper_started=False,outcome_uncertain=False,selection_attempted=False,selection_confirmed=False,continue_attempted=False,continue_returned=False)
class Tests(unittest.TestCase):
 def test_initial_wait(self):
  p=Poll();self.assertFalse(p.due(4,{}));self.assertTrue(p.due(5,{}))
 def test_bounded_retry(self):
  p=Poll();self.assertTrue(p.due(5,{}));self.assertFalse(p.due(14,no_target()));self.assertTrue(p.due(15,no_target()))
 def test_retry_cap(self):
  p=Poll();self.assertEqual(sum(p.due(t,no_target()) for t in range(5,150,10)),12)
 def test_no_retry_after_helper(self):
  p=Poll();p.due(5,{});r=no_target();r['helper_started']=True;self.assertFalse(p.due(15,r))
 def test_no_retry_after_uncertainty(self):
  p=Poll();p.due(5,{});r=no_target();r['outcome_uncertain']=True;self.assertFalse(p.due(15,r))
 def test_no_retry_page_mismatch(self):
  p=Poll();p.due(5,{});r=no_target();r['status']='page_not_language';self.assertFalse(p.due(15,r))
 def test_no_retry_after_any_action(self):
  for k in ('selection_attempted','selection_confirmed','continue_attempted','continue_returned'):
   p=Poll();p.due(5,{});r=no_target();r[k]=True;self.assertFalse(p.due(15,r))
 def test_no_retry_incomplete_result(self):
  p=Poll();p.due(5,{});self.assertFalse(p.due(15,dict(status='no_targets')))
 def test_snapshot_bound(self):
  r={'gui_observations':[]}
  for n in range(12):keep(r,n)
  r['gui_observations'].append('final');self.assertEqual(r['gui_observations'],[0,11,'final'])
