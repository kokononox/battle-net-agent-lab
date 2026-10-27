import unittest,json,copy
import form_details as f
import report
class Details(unittest.TestCase):
 def test_blank(self):self.assertEqual(f.validate(f.blank()),f.blank())
 def test_paths_only(self):
  d={'game_dir':{'default':'C:/PRIVATE_USER','dirname':'PRIVATE','game_dir':'PRIVATE','error':800,'required_space':130*1024**3},'language':{'list':[{'locale':'enUS','name':'English'},{'locale':'deDE','name':'German'}],'speech':[],'text':[],'error':704},'eula':{'error':0,'eula':False}}
  r=f.describe(d);text=json.dumps(r);self.assertEqual(r['status'],'observed');self.assertNotIn('PRIVATE',text);self.assertNotIn('English',text);self.assertEqual(r['recognized_language_locales'],['deDE','enUS']);self.assertEqual(r['required_space_bytes'],130*1024**3);self.assertFalse(r['eula_flag'])
 def test_untrusted_labels(self):
  r=f.describe({'language':{'PRIVATE_VALUE':'SECRET'}});self.assertEqual(r['unknown_member_count'],1);self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('SECRET',json.dumps(r))
 def test_unknown_locale(self):
  r=f.describe({'language':{'text':['PRIVATE','enUS']}});self.assertEqual(r['language_unknown_string_count'],1);self.assertNotIn('PRIVATE',json.dumps(r))
 def test_no_locale_outside_language(self):self.assertEqual(f.describe({'shortcut':'enUS'})['recognized_language_locales'],[])
 def test_legal_presence_only(self):
  r=f.describe({'eula':{'eula':True,'text':'SECRET','url':'https://PRIVATE'}});self.assertTrue(r['eula_text_or_link_in_allowlisted_members']);self.assertTrue(r['eula_flag']);self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('PRIVATE',json.dumps(r))
 def test_caps(self):
  for d in [None,[],{'language':{'list':['x']*65}},{'language':{'list':[[[[['x']]]]]}},dict.fromkeys([str(x) for x in range(33)])]:self.assertEqual(f.describe(d)['status'],'refused')
 def test_nodes_cap(self):self.assertEqual(f.describe({'language':{'list':[{k:'PRIVATE' for k in ('name','locale','text')}]*64}})['status'],'refused')
 def test_bad_space(self):
  for v in (True,-1,2**51,1.5,'PRIVATE'):self.assertIsNone(f.describe({'game_dir':{'required_space':v}})['required_space_bytes'])
 def test_injected_label(self):
  r=f.describe({'language':{}});r['nodes'][0]['path']=['PRIVATE'];self.assertRaises(ValueError,f.validate,r)
 def test_fixed_fields(self):
  r=f.blank();r['secret']='SECRET';self.assertRaises(ValueError,f.validate,r)
 def test_unobserved_values_refused(self):
  r=f.blank();r['eula_flag']=False;self.assertRaises(ValueError,f.validate,r)
 def test_report_requires_request(self):
  r=report.blank('a'*40,'1');r['form_details']=f.describe({'language':{}});self.assertRaises(ValueError,report.validate,r)
if __name__=='__main__':unittest.main()
