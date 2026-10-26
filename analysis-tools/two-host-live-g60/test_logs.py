import unittest,json
from log_diagnosis import classify_line
class T(unittest.TestCase):
 def test_noise(self):self.assertIsNone(classify_line('normal CPU device serial SECRET'))
 def test_path_not_exported(self):
  r=classify_line('ERROR CreateProcess failed error=5 at C:/Users/SECRETNAME/Agent.exe token=SUPERSECRET')
  self.assertIn('process_launch',r['classes']);self.assertEqual(r['named_numeric_diagnostics'],[{'field':'error','value':5}]);self.assertNotIn('SECRET',json.dumps(r))
 def test_code(self):self.assertEqual(classify_line('BLZBNTBTS0000004A')['blizzard_error_codes'],['BLZBNTBTS0000004A'])
 def test_hex_only_named_error(self):
  r=classify_line('ERROR pointer 0x12345678 hresult=0x80070005');self.assertEqual(r['hex_error_tokens'],['0x80070005'])
 def test_fixed_host_only(self):
  r=classify_line('ERROR unknown.secret.invalid us.version.battle.net');self.assertEqual(r['approved_host_mentions'],['us.version.battle.net']);self.assertNotIn('unknown.secret',str(r))
