import json,unittest
from pathlib import Path
from cdn_index import parse_cdn_index
class Tests(unittest.TestCase):
 def test_actual_public_archive(self):
  p=Path(__file__).parent;r=json.loads((p/'reports/ACTUAL-ARCHIVE-FIXTURE.json').read_bytes());raw=(p/'research/fixtures'/('archive-'+r['archive_key']+'.index')).read_bytes();index=parse_cdn_index(raw,r['archive_key'],len(raw));self.assertEqual(index.route_kind,'archive');self.assertEqual(index.sha256,r['sha256']);self.assertEqual(len(index.entries),r['records']);self.assertEqual(index.lookup('2bf8296553eb812b17ced6e1b07036d3',52),())
if __name__=='__main__':unittest.main()
