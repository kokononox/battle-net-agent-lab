import unittest
from required_set import parse_expression,select_bitmap,selected_indices,windows_relative_path,install_candidates,download_candidate_summary
from release_core import InvalidRelease
class Tests(unittest.TestCase):
 def setUp(self):self.tags=[(0,'Windows',1,b'\xf0'),(1,'OSX',1,b'\x0f'),(2,'enUS',3,b'\xcc'),(3,'speech',5,b'\xaa'),(4,'text',5,b'\x55')]
 def bad(self,fn,*args):
  with self.assertRaises(InvalidRelease):fn(*args)
 def test_and(self):self.assertEqual(select_bitmap(self.tags,8,'Windows enUS')[0],b'\xc0')
 def test_or_clauses(self):self.assertEqual(select_bitmap(self.tags,8,'Windows enUS speech:Windows enUS text')[0],b'\xc0')
 def test_optional_present(self):self.assertEqual(select_bitmap(self.tags,8,'Windows enUS speech?')[0],b'\x80')
 def test_optional_missing_audited(self):
  b,r=select_bitmap(self.tags,8,'Windows acct-IRN?');self.assertEqual(b,b'\xf0');self.assertEqual(r['clauses'][0]['optional_tags_absent'],['acct-IRN']);self.assertFalse(r['required_set_selected'])
 def test_missing_required(self):self.bad(select_bitmap,self.tags,8,'Linux')
 def test_no_constraint(self):self.bad(select_bitmap,self.tags,8,'unknown?')
 def test_padding_masked(self):self.assertEqual(select_bitmap([(0,'enUS',3,b'\xff\xff')],9,'enUS')[0],b'\xff\x80')
 def test_msb_indices(self):self.assertEqual(list(selected_indices(b'\x81\xff',9)),[0,7,8])
 def test_duplicate_tag(self):self.bad(select_bitmap,self.tags+[(5,'Windows',1,b'\xff')],8,'Windows')
 def test_bad_bitmap_width(self):self.bad(select_bitmap,[(0,'Windows',1,b'')],8,'Windows')
 def test_boolean_count(self):self.bad(select_bitmap,self.tags,True,'Windows')
 def test_clause_empty(self):self.bad(parse_expression,'Windows:')
 def test_term_duplicate(self):self.bad(parse_expression,'Windows Windows?')
 def test_clause_duplicate(self):self.bad(parse_expression,'Windows:Windows')
 def test_unsupported_grammar(self):
  for s in ['Windows|OSX','!Windows','Windows??','Windows\tenUS','Windows\nenUS','*','Windows;cmd']:self.bad(parse_expression,s)
 def test_safe_path(self):self.assertEqual(windows_relative_path('_retail_\\Wow.exe'),'_retail_/Wow.exe')
 def test_traversal_and_absolute(self):
  for s in ['../x','a/../x','a/./x','G:\\game','/etc/a','\\\\server\\a','a//b','a/','a:stream','a.','a /b','a\x00b','a\nb']:self.bad(windows_relative_path,s)
 def test_device_names(self):
  for s in ['CON','con.txt','NUL.bin','a/COM1.exe','LPT².dat','CONIN$']:self.bad(windows_relative_path,s)
 def test_noncanonical_unicode(self):self.bad(windows_relative_path,'e\u0301.txt')
 def test_long_component(self):self.bad(windows_relative_path,'a'*256)
 def rows(self):return [(0,'Wow.exe',b'a'*16,5),(1,'data/file',b'b'*16,9)]
 def test_install_selection(self):self.assertEqual(len(install_candidates(self.rows(),b'\x80')),1)
 def test_case_collision(self):self.bad(install_candidates,[(0,'Wow.exe',b'a'*16,5),(1,'WOW.EXE',b'b'*16,5)],b'\xc0')
 def test_directory_collision(self):self.bad(install_candidates,[(0,'Data',b'a'*16,5),(1,'DATA/file',b'b'*16,5)],b'\xc0')
 def test_unselected_path_not_opened(self):self.assertEqual(len(install_candidates([(0,'Wow.exe',b'a'*16,5),(1,'../bad',b'b'*16,5)],b'\x80')),1)
 def test_download_total_not_network_estimate(self):
  r=download_candidate_summary([(0,b'a'*16,10,0),(1,b'b'*16,20,1)],b'\xc0',2);self.assertEqual(r['unique_encoded_object_bytes_if_all_selected_candidates_missing'],30);self.assertIsNone(r['required_network_download_bytes'])
 def test_download_duplicate(self):self.bad(download_candidate_summary,[(0,b'a'*16,10,0),(1,b'a'*16,10,1)],b'\xc0',2)
 def test_download_truncation(self):self.bad(download_candidate_summary,[(0,b'a'*16,10,0)],b'\xc0',2)
 def test_download_gap(self):self.bad(download_candidate_summary,[(1,b'a'*16,10,0)],b'\x80',1)
 def test_order(self):self.bad(install_candidates,[(1,'safe',b'a'*16,5)],b'\x80')
if __name__=='__main__':unittest.main()
