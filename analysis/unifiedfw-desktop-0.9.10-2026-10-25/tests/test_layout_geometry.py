from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class LayoutGeometryTests(unittest.TestCase):
 def setUp(self):self.s=(ROOT/'app/ui-layout.ps1').read_text('utf-8-sig')
 def test_point_uses_explicit_scalar_argument_list(self):
  self.assertIn('System.Drawing.Point -ArgumentList @($left,$top)',self.s);self.assertNotIn('New-Object Drawing.Point($area.Left+8,$area.Top+8)',self.s)
 def test_size_uses_explicit_scalar_arguments(self):
  self.assertIn('System.Drawing.Size -ArgumentList @($minimumWidth,$minimumHeight)',self.s);self.assertIn('System.Drawing.Size -ArgumentList @($width,$height)',self.s)
 def test_both_windows_share_the_tested_geometry_helper(self):
  self.assertIn('Set-WindowBoundsForArea $Window $area',self.s);self.assertIn('$form.Add_Shown({Fit-WorkingArea $form})',self.s);self.assertIn('$livePopup.Add_Shown({Fit-WorkingArea $livePopup})',self.s)
 def test_geometry_helper_does_not_touch_state_or_native(self):
  s=self.s.split('function Set-WindowBoundsForArea',1)[1].split('function Fit-WorkingArea',1)[0]
  for x in ('BeginOp','WriteAll','native_','hosts_','store.','Stop-Process'):self.assertNotIn(x,s)
if __name__=='__main__':unittest.main()
