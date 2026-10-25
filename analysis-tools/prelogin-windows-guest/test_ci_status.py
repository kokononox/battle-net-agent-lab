import unittest
from ci_status import status
class Tests(unittest.TestCase):
 def test_started(self):self.assertFalse(status('a'*40,'1','dispatched')['windows_boot_claimed'])
 def test_completed_failure(self):self.assertEqual(status('a'*40,'1','completed','success','failure','failure')['preparation'],'failure')
 def test_no_raw_data(self):self.assertRaises(ValueError,status,'a'*40,'1','completed','private log')
 def test_no_unknown_phase(self):self.assertRaises(ValueError,status,'a'*40,'1','booted')
 def test_source_required(self):self.assertRaises(ValueError,status,'main','1','dispatched')
 def test_run_required(self):self.assertRaises(ValueError,status,'a'*40,'path','dispatched')
