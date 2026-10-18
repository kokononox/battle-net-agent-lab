import unittest
from tag_crosscheck import check_install_download_tags
from release_core import InvalidRelease
class Tests(unittest.TestCase):
 def setUp(self):self.it=[(0,'Windows',1,b'\x80'),(1,'OSX',1,b'\x40')];self.dt=[(0,'Windows',1,b'\x80'),(1,'OSX',1,b'\x80')];self.rows=[(0,'a',b'c'*16,5),(1,'b',b'c'*16,5)];self.links=[(0,b'c'*16,b'e'*16,0,5),(1,b'c'*16,b'e'*16,0,5)]
 def test_union_for_variants(self):self.assertEqual(check_install_download_tags(self.it,self.rows,self.dt,self.links)['unique_content_keys_checked'],1)
 def test_not_vendor_oracle(self):self.assertFalse(check_install_download_tags(self.it,self.rows,self.dt,self.links)['vendor_policy_qualified'])
 def test_disagreement(self):
  with self.assertRaises(InvalidRelease):check_install_download_tags(self.it,self.rows,[(0,'Windows',1,b'\x80'),(1,'OSX',1,b'\x00')],self.links)
 def test_missing_link(self):
  with self.assertRaises(InvalidRelease):check_install_download_tags(self.it,self.rows,self.dt,self.links[:1])
 def test_other_schema(self):
  with self.assertRaises(InvalidRelease):check_install_download_tags(self.it,self.rows,self.dt[:1],self.links)
 def test_ambiguous_representation(self):
  with self.assertRaises(InvalidRelease):check_install_download_tags(self.it,self.rows,self.dt,self.links+[(1,b'c'*16,b'f'*16,1,5)])
if __name__=='__main__':unittest.main()
