import unittest,json
import path_relation as p
class Paths(unittest.TestCase):
 def test_exact(self):self.assertEqual(p.classify('D:\\lab\\target','D:\\lab\\target')['relation'],'exact_string')
 def test_normalized(self):
  for b in ('d:/LAB/target/','D:\\lab\\.\\target','D:\\lab\\other\\..\\target'):
   self.assertEqual(p.classify('D:\\lab\\target',b)['relation'],'normalized_equal')
 def test_child(self):
  r=p.classify('D:\\lab\\target','D:\\lab\\target\\World of Warcraft');self.assertEqual(r['relation'],'child_of_owned_target');self.assertEqual(r['child_depth'],1)
 def test_outside(self):
  for b in ('D:\\lab\\target-evil','D:\\lab\\target\\..\\other','C:\\lab\\target'):
   self.assertEqual(p.classify('D:\\lab\\target',b)['relation'],'outside_owned_target')
 def test_invalid(self):
  for b in ('relative','D:relative','\\rooted','\\\\server\\share\\x','\\\\?\\D:\\x','D:\\x:stream','D:\\x.','D:\\x ','D:\\x\x00','D:\\?x','D:\\x\n',123,''):
   self.assertEqual(p.classify('D:\\lab\\target',b)['relation'],'invalid_path')
 def test_unobserved(self):self.assertEqual(p.classify('D:\\x',None),p.blank())
 def test_no_path_export(self):
  r=p.classify('D:\\PRIVATE\\target','D:\\PRIVATE\\target\\SECRET');self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('SECRET',json.dumps(r));self.assertFalse(r['filesystem_containment_proven'])
 def test_dot_escape(self):
  r=p.classify('D:\\lab\\target','D:\\lab\\target\\sub\\..\\..\\outside');self.assertEqual(r['relation'],'outside_owned_target');self.assertTrue(r['returned_dot_segments'])
 def test_depth_limit(self):self.assertEqual(p.classify('D:\\x','D:\\x\\'+'\\'.join(['s']*33))['relation'],'invalid_path')
 def test_no_fs_proof(self):
  r=p.blank();r['filesystem_containment_proven']=True;self.assertRaises(ValueError,p.validate,r)
 def test_no_arbitrary_label(self):
  r=p.blank();r['relation']='PRIVATE';self.assertRaises(ValueError,p.validate,r)
 def test_no_boolean_depth(self):
  r=p.classify('D:\\x','D:\\x');r['child_depth']=False;self.assertRaises(ValueError,p.validate,r)
if __name__=='__main__':unittest.main()
