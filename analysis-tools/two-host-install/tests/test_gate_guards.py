import os,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import qualify_gate as q
class Guards(unittest.TestCase):
 def test_guard(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/'+q.BRANCH,GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_TWO_HOSTS=q.APPROVAL)
  self.assertTrue(q.authorized(e,'win32'))
  for k in e:
   bad=e.copy();bad[k]='bad';self.assertFalse(q.authorized(bad,'win32'))
  self.assertFalse(q.authorized(e,'linux'))
 def test_guard_before_writes(self):
  with patch.dict(os.environ,{},clear=True),patch('pathlib.Path.write_text') as write,self.assertRaises(SystemExit):q.main()
  write.assert_not_called()
