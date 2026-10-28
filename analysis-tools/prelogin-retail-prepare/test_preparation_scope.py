import unittest
from pathlib import Path
import run_prepare as p

class PreparationScope(unittest.TestCase):
 def test_d11_forbids_transfer(self):
  self.assertFalse(p.transfer_allowed({'RETAIL_PREPARE_SCOPE':'prepare-only-d11'}))
 def test_legacy_transfer_profile_explicit(self):
  self.assertTrue(p.transfer_allowed({'RETAIL_PREPARE_SCOPE':'limited-transfer-c10'}))
  self.assertTrue(p.transfer_allowed({}))
 def test_unknown_scope_refused(self):
  for scope in ('','prepare','true',True,None,'limited-transfer-c11'):
   with self.assertRaises(ValueError):p.transfer_allowed({'RETAIL_PREPARE_SCOPE':scope})
 def test_target_call_requires_scope(self):
  text=Path(p.__file__).read_text()
  self.assertIn('if context is not None and allow_transfer:transfer_probe.execute',text)
  self.assertEqual(text.count('transfer_probe.execute('),1)
 def test_live_workflow_requires_explicit_operation_t6_approval(self):
  root=Path(p.__file__).resolve().parents[2]
  text=(root/'.github/workflows/prelogin-retail-prepare.yml').read_text()
  self.assertIn('RETAIL_PREPARE_SCOPE: limited-transfer-c10',text)
  self.assertIn("github.event.head_commit.message == 'lab: approved bounded readiness Retail operation t6'",text)
  self.assertNotIn("github.event.head_commit.message == 'lab: approved retail prepare c10'",text)

class ShortStartup(unittest.TestCase):
 def test_short_observation_keeps_original_scope_gate(self):
  text=Path(p.__file__).read_text()
  self.assertIn("kwargs.get('seconds')!=120",text)
  self.assertIn("kwargs['seconds']=30",text)
  self.assertIn("r['bootstrap_settle']['observation_seconds']=30",text)
 def test_duration_report_refuses_unbounded_or_wrong_type(self):
  import report
  for v in (0,29,31,121,True,'30'):
   d=report.blank('a'*40,'1');d['bootstrap_settle']['observation_seconds']=v
   with self.assertRaises(ValueError):report.validate(d)
  for v in (30,120):
   d=report.blank('a'*40,'1');d['bootstrap_settle']['observation_seconds']=v;report.validate(d)

if __name__=='__main__':unittest.main()
