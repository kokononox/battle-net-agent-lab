import unittest,copy
from decision import candidate
class T(unittest.TestCase):
 def setUp(self):self.s={'UIA':{'status':'completed_bounded_read','truncated':False,'errors':0,'rows':[{'type':'Window','label':'battle.net setup'},{'type':'Button','label':'continue','enabled':True},{'type':'RadioButton','markers':['english'],'enabled':True}]}}
 def test_candidate(self):self.assertTrue(candidate(self.s))
 def test_duplicate_continue(self):self.s['UIA']['rows'].append(copy.deepcopy(self.s['UIA']['rows'][1]));self.assertFalse(candidate(self.s))
 def test_install_not_continue(self):self.s['UIA']['rows'][1]['label']='install';self.assertFalse(candidate(self.s))
 def test_errors(self):self.s['UIA']['errors']=1;self.assertFalse(candidate(self.s))
 def test_truncated(self):self.s['UIA']['truncated']=True;self.assertFalse(candidate(self.s))
 def test_disabled(self):self.s['UIA']['rows'][1]['enabled']=False;self.assertFalse(candidate(self.s))
if __name__=='__main__':unittest.main()
