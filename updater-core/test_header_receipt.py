import json,unittest
from pathlib import Path
from release_core import InvalidRelease
from review_header_report import review
class Tests(unittest.TestCase):
 def setUp(self):self.r=json.loads((Path(__file__).parent/'reports/HEADER-DIAGNOSTIC-user.json').read_bytes())
 def test_scope_rejects(self):
  for k,v in [('archive_bytes_read',83),('network_requests',1),('target_fixture_version','99.0.0.99999'),('game_modified',True),('full_ckey_verified',False),('raw_blte_payload_exported',True),('installation_ready',True)]:
   r=dict(self.r);r[k]=v
   with self.assertRaises(InvalidRelease):review(json.dumps(r).encode(),b'')
 def test_zero_prefix_changed(self):
  self.r['header_observation']['header_hex_30']='ff'*30
  with self.assertRaises(InvalidRelease):review(json.dumps(self.r).encode(),b'')
 def test_wrong_copy_rejected(self):
  with self.assertRaises(InvalidRelease):review(json.dumps(self.r).encode(),bytes(40))
 def test_bool_count_rejected(self):
  self.r['network_requests']=False
  with self.assertRaises(InvalidRelease):review(json.dumps(self.r).encode(),b'')
if __name__=='__main__':unittest.main()
