import unittest
from ui_schedule import install_due
class Timing(unittest.TestCase):
 def test_probe_spread(self):
  last=-20;times=[]
  for elapsed in range(165):
   if install_due(elapsed,last,len(times)):times.append(elapsed);last=elapsed
  self.assertEqual(len(times),12);self.assertEqual(times[-1],154)
 def test_no_probe_after_deadline(self):self.assertFalse(install_due(165,0,0))
 def test_no_extra_probe_after_limit(self):self.assertFalse(install_due(160,0,12))
 def test_no_immediate_retry(self):self.assertFalse(install_due(5,4,1))
if __name__=='__main__':unittest.main()
