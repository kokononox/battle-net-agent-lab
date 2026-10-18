import json,unittest
from pathlib import Path
from cdn_index import parse_cdn_index
from cdn_routes import archive_index_plan,locate_in_verified_archive
from release_core import TargetSnapshot
class Tests(unittest.TestCase):
 def test_actual_positive_full_key_size_route(self):
  p=Path(__file__).parent;r=json.loads((p/'reports/UNREAD-PASS-to-share.json').read_bytes())['route'];t=TargetSnapshot.restore(r['target']);req=archive_index_plan(t,(p/'observed-cdn.config').read_bytes())[r['source_index_ordinal']];raw=(p/'research/fixtures'/('archive-'+r['archive_key']+'.index')).read_bytes();index=parse_cdn_index(raw,req.archive_key,len(raw));found=locate_in_verified_archive(index,req,r['ekey'],r['encoded_size']);self.assertEqual(index.sha256,r['index_sha256']);self.assertEqual(found['archive_offset'],268435404);self.assertEqual(found['archive_url'],r['archive_url']);self.assertFalse(found['payload_identity_verified'])
if __name__=='__main__':unittest.main()
