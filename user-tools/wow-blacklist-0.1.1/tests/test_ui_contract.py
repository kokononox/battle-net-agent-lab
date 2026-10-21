import unittest
from pathlib import Path
class UiContract(unittest.TestCase):
 def test_table_and_no_bidi_addresses(self):
  s=(Path(__file__).resolve().parents[1]/'app/ui.ps1').read_text()
  self.assertIn('Windows.Forms.DataGridView',s);self.assertIn("$g.RightToLeft='No'",s)
  for column in ('ip','port','protocol','state','reason','remove'):self.assertIn("'"+column+"'",s)
 def test_apply_stays_open_by_default_and_close_is_explicit(self):
  s=(Path(__file__).resolve().parents[1]/'app/ui.ps1').read_text()
  self.assertIn('$apply.Add_Click({ApplyList $false})',s);self.assertIn('$applyClose.Add_Click({ApplyList $true})',s);self.assertIn('if($j.CloseOnSuccess){$form.Close()}',s)
 def test_delete_apply_and_readonly_status_available(self):
  s=(Path(__file__).resolve().parents[1]/'app/ui.ps1').read_text()
  self.assertIn("BeginOp 'status' (Payload)",s);self.assertIn('RemoveKeys',s);self.assertIn('Ui-Without (Entries) $keys',s)
