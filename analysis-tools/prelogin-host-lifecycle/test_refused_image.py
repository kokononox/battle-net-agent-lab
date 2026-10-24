import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from refused_image import validate,inspect_refused,parse_signature,region

def sig():return dict(trust_status=0,publisher_class='microsoft')
class ReadOnlyTests(unittest.TestCase):
    def make(self,root):
        p=Path(root)/'cmd.exe';p.write_bytes(b'MZ'+b'SYNTHETIC_NONEXECUTABLE_FIXTURE');return p
    def test_reads_but_never_launches_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.make(tmp)
            with patch('refused_image.native_signature',return_value=sig()) as verify:
                d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:False)
            self.assertEqual(d['status'],'metadata_complete');self.assertEqual(d['basename_class'],'cmd.exe');self.assertTrue(d['blocked_before_resume']);self.assertFalse(d['execution_authorized']);self.assertTrue(d['authenticode_valid']);self.assertNotIn(str(p),json.dumps(d));self.assertEqual(verify.call_count,1)
    def test_reparse_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.make(tmp)
            with patch('refused_image.native_signature') as verify:d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:True)
            self.assertEqual(d['status'],'metadata_failed');verify.assert_not_called()
    def test_untrusted_not_promoted(self):
        self.assertRaises(ValueError,parse_signature,b'{"trust_status":-1,"publisher_class":"microsoft"}')
    def test_unsafe_publisher_not_exported(self):
        self.assertRaises(ValueError,parse_signature,b'{"trust_status":0,"publisher_class":"arbitrary private certificate subject"}')
    def test_duplicate_signature_keys_rejected(self):
        self.assertRaises(ValueError,parse_signature,b'{"trust_status":0,"trust_status":1,"publisher_class":"unverified"}')
    def test_changed_image_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.make(tmp)
            def changed(*args):p.write_bytes(b'MZCHANGED');return sig()
            with patch('refused_image.native_signature',side_effect=changed):d=inspect_refused(p,dict(SystemRoot=tmp),lambda p:False)
            self.assertEqual(d['status'],'unstable_image');self.assertIsNone(d['image_file_sha256'])
    def test_unknown_filename_not_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'private-user-name.exe';p.write_bytes(b'MZSYNTHETIC')
            with patch('refused_image.native_signature',return_value=sig()):d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:False)
            self.assertEqual(d['basename_class'],'other');self.assertNotIn('private-user-name',json.dumps(d))
    def test_bad_pe_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'cmd.exe';p.write_bytes(b'notPE')
            with patch('refused_image.native_signature') as verify:d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:False)
            self.assertEqual(d['status'],'metadata_failed');verify.assert_not_called()
    def test_missing_image_safe(self):
        with tempfile.TemporaryDirectory() as tmp:d=inspect_refused(Path(tmp)/'cmd.exe',dict(SYSTEMROOT=tmp),lambda p:False)
        self.assertEqual(d['status'],'metadata_failed')
    def test_region_env_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'System32'/'cmd.exe';p.parent.mkdir();p.touch()
            self.assertEqual(region(p,{'SYSTEMROOT':tmp}),'windows_system32');self.assertEqual(region(p,{'SystemRoot':tmp}),'windows_system32')
    def test_execution_cannot_be_authorized_by_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.make(tmp)
            with patch('refused_image.native_signature',return_value=sig()):d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:False)
        d['execution_authorized']=True;self.assertRaises(ValueError,validate,d)
    def test_raw_extra_field_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.make(tmp)
            with patch('refused_image.native_signature',return_value=sig()):d=inspect_refused(p,dict(SYSTEMROOT=tmp),lambda p:False)
        d['path']='private';self.assertRaises(ValueError,validate,d)
    def test_native_contract_source(self):
        s=Path(__file__).with_name('refused_signature.cs').read_text()
        self.assertIn('if(status==0) publisher=PublisherClass(data.stateData)',s)
        self.assertIn('WTHelperGetProvSignerFromChain',s);self.assertIn('data.stateAction=2',s)
        self.assertNotIn('Process.Start',s);self.assertNotIn('LoadLibrary',s)
if __name__=='__main__':unittest.main()
