import json
import unittest
import test_transfer_probe as fixtures
import finalization_shape as s

class Shape(unittest.TestCase):
 def test_valid_links(self):
  for link in ('/game/wow','http://127.0.0.1:1234/game/wow'):
   for d in ({'game':{'link':link}},{'error':0,'game':{'link':link}},{'link':link,'uid':'wow'}):
    self.assertEqual(s.classify(d,1234)['kind'],'canonical_game_link')
 def test_foreign_or_noncanonical_links_refused(self):
  for link in ('http://evil/game/wow','http://127.0.0.1:1235/game/wow','http://localhost:1234/game/wow','/game/wow?x=1','/game/wow/','/game/wow_classic','http://u:p@127.0.0.1:1234/game/wow','/game/%77ow'):
   self.assertEqual(s.classify({'game':{'link':link}},1234)['kind'],'unknown')
 def test_error_and_unknown_member_refused(self):
  for d in ({'error':True,'link':'/game/wow'},{'error':1,'link':'/game/wow'},{'link':'/game/wow','uid':'other'},{'link':'/game/wow','PRIVATE':'secret'}):
   r=s.classify(d,1234);self.assertEqual(r['kind'],'unknown');self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('secret',json.dumps(r))
 def test_product_state_shape(self):
  for complete in (False,True):self.assertEqual(s.classify({'installed':True,'download_complete':complete},1234)['kind'],'product_state')
  self.assertEqual(s.classify({'installed':1,'download_complete':False},1234)['kind'],'unknown')
 def test_form_preserved(self):self.assertEqual(s.classify(fixtures.final(),1234)['kind'],'form')
 def test_validated_no_extra_shape_members(self):
  d=s.blank();d['private']='secret'
  with self.assertRaises(ValueError):s.validate(d)

class CanonicalObservation(unittest.TestCase):
 def test_link_response_never_posts_update(self):
  helper=fixtures.Transfer();r,conn=helper.simulate(final_response={'game':{'link':'http://127.0.0.1:1234/game/wow'}})
  posts=[c.args for c in conn.request.call_args_list if c.args[0]=='POST']
  self.assertEqual(posts,[('POST','/install/wow')]);self.assertFalse(r['transfer']['start_attempted'])
  self.assertEqual(r['transfer']['status'],'canonical_game_link_observed');self.assertEqual(r['transfer']['polls'],4)
 def test_product_state_never_posts_update(self):
  helper=fixtures.Transfer();r,conn=helper.simulate(final_response={'installed':True,'download_complete':False})
  self.assertEqual(r['transfer']['status'],'product_state_observed')
  self.assertTrue(r['transfer']['baseline_progress']['installed']);self.assertFalse(r['transfer']['baseline_progress']['download_complete'])
  self.assertFalse(r['transfer']['start_attempted'])
  self.assertEqual([c.args for c in conn.request.call_args_list if c.args[0]=='POST'],[('POST','/install/wow')])
 def test_unknown_response_not_called_server_refusal(self):
  helper=fixtures.Transfer();r,conn=helper.simulate(final_response={'PRIVATE':'secret'})
  self.assertEqual(r['transfer']['status'],'response_schema_unrecognized');self.assertEqual(conn.request.call_count,1)

if __name__=='__main__':unittest.main()
