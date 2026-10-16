import copy,hashlib,json,socket,tempfile,unittest,zipfile,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import portable_export as p
import portable_run as r
import source_binding as b
import patch_audit as a
from test_encoding_target import fixture

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.code=Path(p.__file__).resolve().parent
        self.encoding=self.root/'original-encoding';self.raw,_,_,_=fixture();self.encoding.write_bytes(self.raw)
        self.payload={n:b'synthetic public fixture' for n in r.PAYLOAD}
        self.out=self.root/'output'
    def tearDown(self):self.temp.cleanup()
    def export(self,watch=None,ck=None,payload=None,out=None):
        return p.write_bundle(out or self.out,watch or b.Watch(),self.encoding,ck or a.md5(self.raw),len(self.raw),payload or self.payload,self.code)
    def test_zip_fixed_whitelist_no_network_or_input_changes(self):
        before=self.encoding.read_bytes()
        with patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):archive,report=self.export()
        self.assertEqual(self.encoding.read_bytes(),before);self.assertTrue(report['zip_crc_readback_verified'])
        with zipfile.ZipFile(archive) as z:
            names=z.namelist();self.assertEqual(len(names),len(r.FIXED)+1)
            self.assertFalse(any('PRIVATE' in n or n.endswith('.sqlite') or self.root.name in n for n in names))
            manifest=json.loads(z.read('Portable-Retail-Sample/PORTABLE-MANIFEST.json'))
            for name,info in manifest['files'].items():
                raw=z.read('Portable-Retail-Sample/'+name)
                self.assertEqual(hashlib.sha256(raw).hexdigest(),info['sha256']);self.assertEqual(len(raw),info['bytes'])
            self.assertNotIn(str(self.root),json.dumps(manifest))
    def test_bad_encoding_hash_no_publish(self):
        with self.assertRaises(b.BindingError):self.export(ck='0'*32)
        self.assertFalse((self.out/'Portable-Retail-Sample.zip').exists());self.assertFalse((self.out/'Portable-Retail-Sample.zip.partial').exists())
    def test_existing_output_rejected(self):
        self.out.mkdir()
        with self.assertRaises(b.BindingError):self.export()
    def test_extra_private_payload_rejected(self):
        payload={**self.payload,'PRIVATE-secret.json':b'secret'}
        with self.assertRaises(b.BindingError):self.export(payload=payload)
        self.assertFalse(self.out.exists())
    def test_missing_payload_rejected(self):
        payload=dict(self.payload);payload.pop('target.decoded')
        with self.assertRaises(b.BindingError):self.export(payload=payload)
    def test_insufficient_space_rejected(self):
        with patch.object(p.shutil,'disk_usage',return_value=type('Usage',(),{'free':0})()):
            with self.assertRaises(b.BindingError):self.export()
        self.assertFalse(self.out.exists())
    def test_symlink_output_parent_rejected(self):
        dest=self.root/'real';dest.mkdir();link=self.root/'link';link.symlink_to(dest,target_is_directory=True)
        with self.assertRaises(b.BindingError):self.export(out=link/'new')
    def test_changed_watched_input_rejected(self):
        watch=b.Watch();watch.file(self.encoding);self.encoding.write_bytes(self.raw+b'!')
        with self.assertRaises(b.BindingError):self.export(watch=watch)
    def test_manifest_verification_roundtrip(self):
        archive,_=self.export();dest=self.root/'extract';dest.mkdir()
        with zipfile.ZipFile(archive) as z:z.extractall(dest)
        extracted=dest/'Portable-Retail-Sample'
        result=r.check_manifest(extracted,b.Watch());self.assertEqual(result['format'],'portable-retail-fixture-1')
        (extracted/'source.blte').write_bytes(b'changed')
        with self.assertRaises(b.BindingError):r.check_manifest(extracted,b.Watch())
    def test_self_generated_archive_has_no_absolute_entries(self):
        archive,_=self.export()
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                self.assertFalse(info.filename.startswith('/'));self.assertNotIn('..',Path(info.filename).parts)
    def test_wrong_manifest_file_set_rejected(self):
        root=self.root/'bad';root.mkdir();(root/'PORTABLE-MANIFEST.json').write_text(json.dumps({'format':'portable-retail-fixture-1','files':{'../secret':{}}}))
        with self.assertRaises(b.BindingError):r.check_manifest(root,b.Watch())
    def test_summary_contains_no_path(self):
        archive,report=self.export();self.assertNotIn(str(self.root),json.dumps(report))
        self.assertFalse(report['private_reports_exported']);self.assertFalse(report['databases_exported'])
