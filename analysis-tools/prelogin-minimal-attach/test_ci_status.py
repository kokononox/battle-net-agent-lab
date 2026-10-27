import unittest
from ci_status import status
class Tests(unittest.TestCase):
 def test_dispatch(self):self.assertEqual(status('a'*40,'1','dispatched')['observation'],'unknown')
 def test_failure_typed(self):self.assertEqual(status('a'*40,'1','completed','success','failure','skipped','failure')['tests'],'failure')
 def test_no_raw_exception(self):self.assertRaises(ValueError,status,'a'*40,'1','completed','PRIVATE')
 def test_no_invalid_identity(self):self.assertRaises(ValueError,status,'main','1','dispatched')
