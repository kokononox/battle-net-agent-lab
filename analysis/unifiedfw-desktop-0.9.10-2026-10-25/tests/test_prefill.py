import pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class PrefillTests(unittest.TestCase):
 def setUp(self):self.s=(ROOT/'app/ui-context.ps1').read_text('utf-8-sig')
 def test_presentation_only_no_mutation_or_submission(self):
  for x in ('BeginOp','monitor_stage','observed_add','WriteAllText','Set-Content','native_apply','hosts_apply','GetHostEntry','inspect_executable'):self.assertNotIn(x,self.s)
 def test_all_six_views_get_context_actions(self):
  for x in ('$liveGrid', '$popupGrid', '$domainMain', '$domainPopup', '$processGrid', '$popupProcessGrid'):self.assertIn(x,self.s)
  self.assertIn('CellMouseDown',self.s);self.assertIn('SelectedRows.Count -ne 1',self.s)
 def test_only_target_text_changes_no_program_or_transport(self):
  self.assertIn('$whitelist.Text=$text',self.s);self.assertIn('Merge-WhitelistDraft',self.s)
  for x in ('$proto.Selected', '$port.Value=', '$programGrid.Rows', 'CheckedIds', 'store.'):self.assertNotIn(x,self.s)
 def test_domain_to_hosts_and_whitelist_draft_limit(self):
  self.assertIn("if($Destination -ceq 'blacklist'){Stage-ObservedDraft $row $chosen;return}",self.s);self.assertIn('فقط پیش‌نویس',self.s)
 def test_existing_draft_appended_not_replaced(self):
  self.assertIn('return $Existing+',self.s);self.assertIn('seen.ContainsKey',self.s);self.assertIn('نه جایگزین',self.s)
 def test_old_stage_button_also_prefills_only(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertIn("Prefill-Observed $liveGrid 'endpoint' 'blacklist'",s);self.assertNotIn("BeginOp 'monitor_stage'",s)
if __name__=='__main__':unittest.main()
