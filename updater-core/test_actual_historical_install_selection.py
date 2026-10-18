import hashlib,unittest
from pathlib import Path
from catalogue_readers import parse_install
from required_set import select_bitmap,install_candidates
class Tests(unittest.TestCase):
 def test_uploaded_historical_install_candidate_only(self):
  raw=(Path(__file__).parent/'research/fixtures/install-70391.metadata').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'1e9a735e4ec5ffe7fc10b9f39e347cf6f9745a89d15ba700a3982399644d92a6');tags,rows=parse_install(raw);bits,receipt=select_bitmap(tags,len(rows),'Windows x86_64 EU? enUS speech?:Windows x86_64 EU? enUS text?');paths=install_candidates(rows,bits);self.assertEqual(len(paths),39);self.assertFalse(receipt['vendor_policy_qualified']);self.assertFalse(receipt['required_set_selected']);self.assertFalse(receipt['apply_authorized'])
if __name__=='__main__':unittest.main()
