import ast,unittest
from pathlib import Path
class DurationTests(unittest.TestCase):
 def setUp(self):
  self.s=(Path(__file__).resolve().parents[1]/'app/observe.py').read_text();self.t=ast.parse(self.s)
 def test_native_runtime_is_sixty(self):
  self.assertIn("'/Runtime','60'",self.s);self.assertNotIn("'/Runtime','20'",self.s)
 def test_report_duration(self):self.assertIn('native_runtime_limit_seconds=60',self.s)
 def test_watchdog_matches_report(self):
  self.assertIn("started>=75:reason='watchdog_75_seconds'",self.s);self.assertIn('watchdog_limit_seconds=75',self.s)
 def test_old_duration_labels_absent(self):
  self.assertNotIn('20 seconds',self.s);self.assertNotIn('20-second system-wide',self.s);self.assertNotIn('watchdog_30_seconds',self.s)
 def test_safety_budgets_preserved(self):
  self.assertIn('size>=1024**3',self.s);self.assertIn('timeout=120',self.s);self.assertIn('hard_disk_cap_guaranteed=False',self.s)
 def test_version(self):self.assertIn("'version':'0.2.2'",self.s)
