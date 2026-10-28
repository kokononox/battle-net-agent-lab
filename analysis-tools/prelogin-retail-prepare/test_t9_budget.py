import unittest,shutil,subprocess,tempfile
from pathlib import Path
import guard_report as g
from test_guard_report import rec
from test_network_diagnostics import blank
class Budget(unittest.TestCase):
 def expanded(self):
  r=rec('observe');r.update(schema='bnet-retail-supervisor-5',budget_profile='approved-2g-512m-t9',network_diagnostics=blank(),phase_arming_acknowledged=False,phase_baseline_policy='acknowledged_pre_request_snapshot',network_threshold_bytes=2147483648,phase_network_threshold_bytes=536870912);return r
 def test_approved_exact_limits(self):g.receipt(self.expanded())
 def test_no_arbitrary_cap_changes(self):
  for k in ('time_limit_ms','disk_reserve_bytes','phase_time_limit_ms','phase_network_threshold_bytes','network_threshold_bytes'):
   r=self.expanded();r[k]+=1
   with self.assertRaises(ValueError):g.receipt(r)
 def test_profile_required_for_expanded_limits(self):
  r=self.expanded();r['budget_profile']='legacy-c10'
  with self.assertRaises(ValueError):g.receipt(r)
 def test_fixture_must_retain_original_caps(self):
  r=rec('fixture_timeout');r.update(schema='bnet-retail-supervisor-5',budget_profile='approved-2g-512m-t9',network_diagnostics=blank(),phase_arming_acknowledged=False,phase_baseline_policy='acknowledged_pre_request_snapshot')
  with self.assertRaises(ValueError):g.receipt(r)
 @unittest.skipUnless(shutil.which('g++'),'compiler unavailable')
 def test_actual_shared_native_policy(self):
  with tempfile.TemporaryDirectory()as t:
   exe=str(Path(t)/'test');r=subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror',str(Path(__file__).with_name('budget_profile_test.cpp')),'-o',exe],capture_output=True,timeout=30);self.assertEqual(r.returncode,0);self.assertEqual(subprocess.run([exe],timeout=5).returncode,0)
if __name__=='__main__':unittest.main()
