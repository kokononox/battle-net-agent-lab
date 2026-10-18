import hashlib,json,unittest
from pathlib import Path
from catalogue_readers import parse_install
from required_set import select_bitmap,install_candidates
from candidate_plan import reference_mask
from config_binding import bind
from release_core import TargetSnapshot
class Tests(unittest.TestCase):
 def test_actual_target_install_identity_and_candidate(self):
  p=Path(__file__).parent;r=json.loads((p/'reports/METADATA-RECOVERED-VERIFIED-to-share.json').read_bytes());t=TargetSnapshot.restore(r['target']);b=bind(t,(p/'observed-build.config').read_bytes(),(p/'observed-cdn.config').read_bytes());s=next(x for x in b['manifest_descriptors']if x['name']=='install');proof=next(x for x in r['metadata']if x['name']=='install');raw=(p/'research/fixtures/install-70448.metadata').read_bytes();self.assertEqual(len(raw),s['decoded_size']);self.assertEqual(hashlib.md5(raw).hexdigest(),s['ckey']);self.assertEqual(hashlib.sha256(raw).hexdigest(),proof['decoded_sha256']);tags,rows=parse_install(raw);expr='Windows x86_64 EU? enUS speech?:Windows x86_64 EU? enUS text?';bits,audit=select_bitmap(tags,len(rows),expr);self.assertEqual(bits,reference_mask(tags,len(rows),expr));self.assertEqual(len(install_candidates(rows,bits)),39);self.assertFalse(audit['vendor_policy_qualified']);self.assertFalse(audit['installation_ready'])
if __name__=='__main__':unittest.main()
