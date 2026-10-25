import json,os,pathlib,socket,subprocess,sys,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from resolver_diagnostic import *
class DiagnosticTests(unittest.TestCase):
 def test_categories(self):
  c=classify(['0.0.0.0','::','::ffff:0.0.0.0','127.0.0.1','8.8.8.8','10.0.0.1','bad'])
  self.assertEqual(c,dict(unspecified=3,loopback=1,public=1,other_nonpublic=1,invalid=1))
 def test_no_raw_answers(self):self.assertNotIn('8.8.8.8',json.dumps(result('answers',counts=classify(['8.8.8.8']))))
 def test_dns_errors_not_accepted_as_sinkhole(self):
  with patch('socket.getaddrinfo',side_effect=socket.gaierror(11001,'private raw text')):
   p=child(DOMAINS[0],'any');self.assertEqual(p['status'],'dns_error');self.assertEqual(p['error_code'],11001);self.assertEqual(sum(p['answer_classes'].values()),0);self.assertNotIn('private',json.dumps(p))
 def test_timeout_distinct(self):self.assertEqual(probe(DOMAINS[0],'any',{},Mock(side_effect=subprocess.TimeoutExpired('child',8)))['status'],'timeout')
 def test_helper_failure_distinct(self):self.assertEqual(probe(DOMAINS[0],'any',{},Mock(return_value=subprocess.CompletedProcess([],1,stdout=b'')))['status'],'helper_nonzero')
 def test_output_rejected(self):self.assertEqual(probe(DOMAINS[0],'any',{},Mock(return_value=subprocess.CompletedProcess([],0,stdout=b'raw traceback')))['status'],'output_rejected')
 def test_child_no_network_selftest(self):
  env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','TEMP','TMP'}}
  p=probe('0.0.0.0','any',env);self.assertEqual(p['status'],'answers');self.assertGreater(p['answer_classes']['unspecified'],0)
 def test_guard(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/'+BRANCH,GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_DNS_DIAG=APPROVAL,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123')
  self.assertTrue(authorized(e,'win32'))
  for k in e:
   bad=e.copy();bad[k]='bad';self.assertFalse(authorized(bad,'win32'),k)
  self.assertFalse(authorized(e,'linux'))
 def test_guard_precedes_disk_write(self):
  with patch.dict(os.environ,{},clear=True),patch('pathlib.Path.write_text') as write, self.assertRaises(SystemExit):main()
  write.assert_not_called()
 def test_unknown_input_refused(self):
  with self.assertRaises(ValueError):child('unapproved.invalid','any')
 def test_no_errors_with_answers(self):
  with self.assertRaises(ValueError):validate_probe(result('dns_error',counts=classify(['8.8.8.8'])))
if __name__=='__main__':unittest.main()
