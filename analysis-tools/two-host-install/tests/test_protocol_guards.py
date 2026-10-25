import os,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import diagnose_protocol as d
class ProtocolGuards(unittest.TestCase):
 def test_exact_names(self):
  self.assertEqual(set(d.HOSTS),{'level3.blizzard.com','us.version.battle.net'})
 def test_no_writes_without_approval(self):
  with patch.dict(os.environ,{},clear=True),patch('pathlib.Path.write_text') as w,patch('socket.getaddrinfo') as net,self.assertRaises(SystemExit):d.main()
  w.assert_not_called();net.assert_not_called()
 def test_authorization(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Windows',GITHUB_REF='refs/heads/research/battlenet-minimal-install-isolation-2026-10-25',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',BNET_TWO_HOSTS=d.APPROVAL)
  self.assertTrue(d.authorized(e,'win32'))
  for k in e:
   bad=e.copy();bad[k]='bad';self.assertFalse(d.authorized(bad,'win32'))
  self.assertFalse(d.authorized(e,'linux'))
