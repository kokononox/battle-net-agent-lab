import unittest
from pathlib import Path
from cdn_index import parse_cdn_index
class Tests(unittest.TestCase):
 def test_pinned_public_loose_index(self):
  p=Path(__file__).parent/'research/fixtures/pinned-file.index';x=parse_cdn_index(p.read_bytes(),'500be77a72250381888365f7c51e6ea4',560348);self.assertEqual(x.page_count,136);self.assertEqual(len(x.entries),27738);self.assertEqual(x.lookup('2bf8296553eb812b17ced6e1b07036d3',52),());self.assertEqual(x.sha256,'ee91f3aef50a7727bdb7b8bfe2fd0beedb34e85ce2bcb41d2d930b4ff98a0f04')
if __name__=='__main__':unittest.main()
