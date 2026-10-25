import json,tempfile,unittest
from pathlib import Path
from storage_scan import flags,safe_locator,files,blank,validate,scan
ID=b'ABCDEFAB-ABCD-4ABC-ABCD-ABCDEFABCDEF'
class StorageTests(unittest.TestCase):
    def test_json_source_id_exact(self):
        f=flags(json.dumps({'telemetry':{'source_id':ID.decode()}}).encode(),{ID})
        self.assertTrue(f['source_id_key_exact']);self.assertTrue(f['uuid_exact'])
    def test_lowercase_separate(self):
        f=flags(json.dumps({'source_id':ID.decode().lower()}).encode(),{ID})
        self.assertTrue(f['source_id_key_casefold']);self.assertFalse(f['source_id_key_exact'])
    def test_log_not_config_key(self):
        f=flags(b'log event '+ID,{ID});self.assertTrue(f['uuid_exact']);self.assertFalse(f['source_id_key_exact'])
    def test_wrong_value_not_equal(self):
        f=flags(b'{"source_id":"synthetic-other-value"}',{ID});self.assertTrue(f['source_id_literal_present']);self.assertFalse(f['uuid_casefold'])
    def test_utf16_json(self):
        f=flags(json.dumps({'source_id':ID.decode()}).encode('utf-16'),{ID});self.assertTrue(f['source_id_key_exact']);self.assertTrue(f['uuid_exact'])
    def test_duplicate_json_not_accepted_as_key_match(self):
        f=flags(b'{"source_id":"'+ID+b'","source_id":"other"}',{ID});self.assertFalse(f['source_id_key_exact'])
    def test_private_locator_masked(self):
        s=safe_locator(['Agent','Agent.9824','private-user-name',ID.decode(),'agent.db'])
        self.assertEqual(s,'Agent/Agent.9824/*/*/agent.db')
    def test_actual_readonly_file_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'agent.db';raw=b'{"source_id":"'+ID+b'"}';p.write_bytes(raw)
            r=blank('after_first');r['observed_uuid_count']=1;files(r,[('programdata_battlenet',root)],{ID});validate(r)
            self.assertEqual(p.read_bytes(),raw);self.assertEqual(len(r['matches']),1);self.assertTrue(r['matches'][0]['source_id_key_exact']);self.assertNotIn(ID.decode(),json.dumps(r));self.assertFalse(r['provider_read_source_proven'])
    def test_executable_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'agent.exe').write_bytes(ID)
            r=blank('after_first');files(r,[('programdata_battlenet',root)],{ID});self.assertEqual(r['files_read'],0)
    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'real.db';p.write_bytes(ID);(root/'link.db').symlink_to(p)
            r=blank('after_first');files(r,[('programdata_battlenet',root)],{ID});self.assertEqual(r['files_read'],1);self.assertEqual(r['skipped_reparse'],1)
    def test_unknown_id_not_scanned(self):
        r=scan(set(),{},'after_first');self.assertEqual(r['status'],'not_scanned')
    def test_unknown_raw_field_rejected(self):
        r=blank('after_first');r['uuid']=ID.decode();self.assertRaises(ValueError,validate,r)
    def test_locator_cannot_leak_unknown_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'agent.db').write_bytes(ID);r=blank('after_first');files(r,[('programdata_battlenet',root)],{ID});r['matches'][0]['locator']=ID.decode();self.assertRaises(ValueError,validate,r)
    def test_presence_cannot_be_promoted_to_provider_read(self):
        r=blank('after_first');r['provider_read_source_proven']=True;self.assertRaises(ValueError,validate,r)
if __name__=='__main__':unittest.main()
