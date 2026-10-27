import unittest,stat
from unittest.mock import Mock
from types import SimpleNamespace
import path_guard as p
class Paths(unittest.TestCase):
 def test_blank(self):self.assertEqual(p.validate(p.blank()),p.blank())
 def test_metadata_chain(self):
  read=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0));r=p.inspect('D:/owned','D:/owned',read);self.assertEqual(r['status'],'verified_existing_chain');self.assertGreater(r['existing_components_checked'],0);self.assertFalse(r['race_free_containment_proven'])
 def test_outside_no_access(self):
  read=Mock();r=p.inspect('D:/owned','C:/outside',read);self.assertEqual(r['status'],'refused');read.assert_not_called()
 def test_reparse(self):
  read=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400));r=p.inspect('D:/owned','D:/owned',read);self.assertTrue(r['reparse_detected']);self.assertEqual(r['status'],'refused');self.assertEqual(read.call_count,1)
 def test_nondirectory(self):self.assertEqual(p.inspect('D:/owned','D:/owned',lambda _:SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0))['status'],'refused')
 def test_error(self):self.assertEqual(p.inspect('D:/owned','D:/owned',Mock(side_effect=PermissionError('PRIVATE')))['status'],'refused')
 def test_missing_root_not_verified(self):self.assertEqual(p.inspect('D:/owned','D:/owned',Mock(side_effect=FileNotFoundError()))['status'],'refused')
 def test_no_race_proof(self):
  r=p.blank();r['race_free_containment_proven']=True;self.assertRaises(ValueError,p.validate,r)
if __name__=='__main__':unittest.main()
