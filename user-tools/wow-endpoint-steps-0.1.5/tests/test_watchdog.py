import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import MagicMock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import main
from core import ENDPOINTS,atomic
class WatchdogTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.p=Path(self.t.name)/('session-'+'a'*32+'.json');i='a'*32
  atomic(self.p,{'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(Path(self.t.name)/'Wow.exe'),**ENDPOINTS[0],'expires':time.time()+300,'parent_pid':123})
  self.k=MagicMock();self.k.OpenProcess.return_value=1;self.k.WaitForSingleObject.return_value=0
 def tearDown(self):self.t.cleanup()
 def test_parent_exit_restores_but_retains_journal_for_main_readback(self):
  with patch.object(main.ctypes,'WinDLL',return_value=self.k,create=True),patch.object(main,'firewall',return_value={'ok':True}) as fw:main.watchdog(self.p)
  fw.assert_called_once_with('remove',self.p);self.assertTrue(self.p.exists());self.assertTrue(self.p.with_suffix('.restored').exists());self.k.CloseHandle.assert_called_once()
 def test_no_parent_handle_no_ready(self):
  self.k.OpenProcess.return_value=0
  with patch.object(main.ctypes,'WinDLL',return_value=self.k,create=True):
   with self.assertRaises(RuntimeError):main.watchdog(self.p)
  self.assertFalse(self.p.with_suffix('.ready').exists())
 def test_cleanup_failure_retains_journal_and_retries_only_cleanup(self):
  with patch.object(main.ctypes,'WinDLL',return_value=self.k,create=True),patch.object(main,'firewall',side_effect=RuntimeError('mock')) as fw,patch.object(main.time,'sleep'):main.watchdog(self.p)
  self.assertEqual(fw.call_count,6);self.assertTrue(self.p.exists());self.assertFalse(self.p.with_suffix('.restored').exists())
if __name__=='__main__':unittest.main()
