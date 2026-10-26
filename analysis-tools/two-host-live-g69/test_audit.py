import unittest,json
from semantic_audit import Audit,variants
from inventory import summarize
class T(unittest.TestCase):
 def feed(self,path,header='',public=(),ids=()):
  a=Audit(public,ids);a.feed('test',('GET '+path+' HTTP/1.1\r\nHost: us.version.battle.net\r\n'+header+'\r\n').encode());self.assertEqual(len(a.rows),1);return a.rows[0]
 def test_query_platform(self):
  r=self.feed('/v2/products/agent/versions?platform=win');self.assertEqual(r['query_parameters'][0]['class'],'platform_or_architecture_literal');self.assertFalse(r['fingerprinting_absence_proven'])
 def test_public_hash(self):
  token='abcdef0123456789abcdef0123456789';r=self.feed('/tpr/agent/config/'+token,public=[token]);self.assertEqual(r['path_segment_classes']['fixed_public_reference_token_exact'],1);self.assertNotIn(token,json.dumps(r))
 def test_hex_not_automatically_public(self):
  r=self.feed('/abc?key=abcdef0123456789abcdef0123456789');self.assertEqual(r['query_parameters'][0]['class'],'opaque_hex_not_proven_content_hash')
 def test_no_raw_query_or_ua(self):
  r=self.feed('/SECRET-PATH?privatekey=SECRET-VALUE','User-Agent: SECRET-UA\r\n');self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['query_parameters'][0]['key'],'<other>')
 def test_local_hash(self):
  v=dict(variants('UNIQUE-MACHINE-NAME'))['sha256'];r=self.feed('/v2/products/agent/versions?id='+v,ids=[('machine_name','sha256',v)]);self.assertEqual(r['verdict'],'suspicious_local_identifier_match');self.assertNotIn(v,json.dumps(r))
 def test_body_token(self):
  a=Audit(identifiers=[('user_name','literal','private-user')]);a.feed(1,b'POST /x HTTP/1.1\r\nHost: level3.blizzard.com\r\nContent-Length: 12\r\n\r\nprivate-user');self.assertTrue(a.rows[0]['body_local_identifier_match'])
 def test_split(self):
  a=Audit();s=b'GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n';a.feed(1,s[:8]);a.feed(1,s[8:]);self.assertEqual(len(a.rows),1)
 def test_public_sequence_not_machine_id(self):
  r=self.feed('/v2/summary?seqn=1234567',public=['@seq:1234567']);self.assertEqual(r['query_parameters'][0]['class'],'fixed_public_sequence_exact');self.assertEqual(r['query_parameters'][0]['key'],'seqn');self.assertTrue(r['route_matches_fixed_public_endpoint']);self.assertNotIn('1234567',json.dumps(r))
 def test_agent_grammar_and_public_version(self):
  r=self.feed('/v2/summary','User-Agent: Agent/1.2.3.4\r\n',public=['1.2.3.4']);self.assertTrue(r['user_agent']['matches_exact_agent_version_only_grammar']);self.assertTrue(r['user_agent']['all_version_groups_match_fixed_public_reference'])
 def test_agent_grammar_rejects_extra_identifier(self):
  r=self.feed('/v2/summary','User-Agent: Agent/1.2.3.4 SECRET-ID\r\n',public=['1.2.3.4']);self.assertFalse(r['user_agent']['matches_exact_agent_version_only_grammar'])
 def test_TimeWait_is_not_live_owner(self):
  _,r=summarize({'processes':[],'target_IP_TCP':[{'OwningProcess':0,'State':'TimeWait','RemotePort':443}],'candidate_limit_hit':False},set());self.assertEqual(r['PID_zero_rows'],1);self.assertEqual(r['unobserved_live_process_owner_rows'],0)
 def test_real_owner(self):
  p={'pid':123,'name':'svchost.exe','signature_status':'Valid','publisher_class':'Microsoft','blizzard_verified':False,'already_observed':False,'image_path':'PRIVATE'}
  _,r=summarize({'processes':[p],'target_IP_TCP':[{'OwningProcess':123,'State':'Established','RemotePort':80}],'candidate_limit_hit':False},set());self.assertEqual(r['unobserved_live_process_owner_rows'],1);self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('123',json.dumps(r))
