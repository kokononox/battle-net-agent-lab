import unittest,tempfile,os
from pathlib import Path
from unittest.mock import patch
import transfer_probe as t,snapshot_status as s
class Snapshot(unittest.TestCase):
 def test_entry_limit_is_censored_not_zero(self):
  with patch.object(t,'file_snapshot',side_effect=ValueError('tree_limit')),patch.object(s,'record')as record:
   self.assertIsNone(t.observe_files(Path('.'),{'source_commit':'a'*40,'run_id':'1'}));record.assert_called_once_with('a'*40,'1','entry_limit')
 def test_security_errors_are_not_censored(self):
  for reason in ('tree_reparse','tree_type','tree_depth','tree_bytes'):
   with patch.object(t,'file_snapshot',side_effect=ValueError(reason)),patch.object(s,'record')as record:
    with self.assertRaises(ValueError):t.observe_files(Path('.'),{'source_commit':'a'*40,'run_id':'1'})
    record.assert_not_called()
 def test_receipt_retains_count_bound_and_no_absence_claim(self):
  r=dict(schema='bnet-retail-snapshot-status-1',source_commit='a'*40,run_id='1',status='entry_limit',entry_limit_events=1,maximum_entries=512,file_absence_proven=False,raw_paths_exported=False);s.validate(r)
  for k in ('file_absence_proven','raw_paths_exported'):
   b=dict(r);b[k]=True
   with self.assertRaises(ValueError):s.validate(b)
 def test_content_check_before_tree_checkpoint(self):
  text=Path(t.__file__).read_text();start=text.index("if method=='GET'and path in")
  sub=text[start:text.index('if session.verify()',start)]
  self.assertLess(sub.index('content.scan()'),sub.index('observe_files('))
if __name__=='__main__':unittest.main()
