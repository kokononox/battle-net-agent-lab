import base64,copy,json,socket,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import staging_sample as s
import source_binding as b
import patch_audit as a
from test_patch_audit import fake_blte,make_patch

class SampleTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name).resolve()
        self.lab=self.root/'Lab';self.lab.mkdir();self.base=self.root/'Tool';self.base.mkdir()
        self.folder=self.root/'Game'/'Data'/'data';self.folder.mkdir(parents=True)
        self.raw,self.ek,self.ck,self.ds=fake_blte(b'ABC');self.patch=make_patch()
        self.archive=self.folder/'data.000';self.archive.write_bytes(self.raw)
        self.fp=b.fp(self.archive.stat())
        self.snap={'directory':str(self.folder),'directory_identity':b.fp(self.folder.stat()),'files':{'data.000':self.fp},'names':['data.000']}
        self.option={'target_ckey':a.md5(b'BAD!'),'target_size':4,'source_ekey':self.ek,'source_size':3,'patch_key':a.md5(self.patch),'patch_size':len(self.patch),'ordinal':0}
        self.obs={'decoded_sha256':a.sha256(b'ABC'),'encoded_sha256':a.sha256(self.raw),'derived_source_ckey':self.ck,'encoded_size':len(self.raw)}
        self.proof={'source_ekey':self.ek,'decoded_size':3,'full_source_ekey_verified':True,'pa_source_decoded_size_verified':True,**self.obs}
        self.prior={'target':{'test':'synthetic-not-retail'},'local_storage_snapshot':self.snap,'watched_files':[{'path':str(self.archive),'fingerprint':self.fp}]}
        self.sel={'archive_name':'data.000','source_ekey':self.ek,'source_size':3,'patch_options':[self.option],'proof':self.proof,'apply_authorized':False,'source_path':str(self.archive),'source_fingerprint':self.fp,'raw_offset':0,'source_offset':0,'span':len(self.raw),'source_encoded_size':len(self.raw)}
        self.private={'format':'private-patch-refs-source-1','target':self.prior['target'],'local_storage_snapshot':self.snap,'selected_source':self.sel,'apply_authorized':False,'watched_files':self.prior['watched_files']}
        self.pfile=self.root/'PRIVATE-Refs-Source.json';self.pfile.write_text(json.dumps(self.private))
        (self.base/'sample.zbsdiff.base64').write_bytes(base64.b64encode(self.patch))
        self.patches=[patch.object(s,'OPTION',self.option),patch.object(s,'OBSERVED',self.obs),patch.object(s,'__file__',str(self.base/'staging_sample.py'))]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.t.cleanup()
    def assertbad(self,change):
        v=copy.deepcopy(self.private);change(v)
        with self.assertRaises(b.BindingError):s.selection(v,self.prior)
    def test_valid_selection(self):self.assertEqual(s.selection(self.private,self.prior),self.sel)
    def test_wrong_target(self):self.assertbad(lambda v:v.update(target={'wrong':True}))
    def test_wrong_snapshot(self):self.assertbad(lambda v:v.update(local_storage_snapshot={}))
    def test_wrong_option(self):self.assertbad(lambda v:v['selected_source'].update(patch_options=[]))
    def test_different_source(self):self.assertbad(lambda v:v['selected_source'].update(source_ekey='00'*16))
    def test_wrong_proof_hash(self):self.assertbad(lambda v:v['selected_source']['proof'].update(decoded_sha256='0'*64))
    def test_unverified_prior(self):self.assertbad(lambda v:v['selected_source']['proof'].update(full_source_ekey_verified=False))
    def test_arbitrary_path_rejected(self):self.assertbad(lambda v:v['selected_source'].update(source_path='/etc/passwd'))
    def test_path_traversal_rejected(self):self.assertbad(lambda v:v['selected_source'].update(archive_name='../data.000'))
    def test_bool_offset_rejected(self):self.assertbad(lambda v:v['selected_source'].update(source_offset=True))
    def test_large_span_rejected(self):self.assertbad(lambda v:v['selected_source'].update(span=100000000))
    def test_wrong_size_rejected(self):self.assertbad(lambda v:v['selected_source'].update(source_encoded_size=9))
    def test_private_not_authorization(self):self.assertbad(lambda v:v.update(apply_authorized=True))
    def test_source_read_and_full_identity(self):
        w=b.Watch();w.snapshot(self.snap);old,proof=s.read_source(self.sel,self.snap,w)
        self.assertEqual(old,b'ABC');self.assertEqual(proof['decoded_sha256'],self.obs['decoded_sha256'])
    def test_changed_source_rejected(self):
        self.archive.write_bytes(self.raw+b'!')
        with self.assertRaises(b.BindingError):s.read_source(self.sel,self.snap,b.Watch())
    def test_source_hash_mismatch_rejected(self):
        self.obs['decoded_sha256']='0'*64
        with self.assertRaises(b.BindingError):s.read_source(self.sel,self.snap,b.Watch())
    def test_synthetic_reconstruction(self):self.assertEqual(s.rebuild(b'ABC',self.patch)[0],b'BAD!')
    def test_wrong_source_decoded_rejected(self):
        with self.assertRaises(a.AuditError):s.rebuild(b'ABD',self.patch)
    def test_patch_corruption_rejected(self):
        raw=self.patch[:-1]+bytes([self.patch[-1]^1])
        with self.assertRaises(a.AuditError):s.rebuild(b'ABC',raw)
    def test_wrong_target_ckey_rejected(self):
        self.option['target_ckey']='0'*32
        with self.assertRaises(a.AuditError):s.rebuild(b'ABC',self.patch)
    def run_fixture(self,output):
        with patch.object(b,'bind',return_value=({},self.prior)),patch.object(b,'load_metadata',return_value=([SimpleNamespace(**self.option)],{},{})),patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            return s.run(self.lab,self.pfile,output=output)
    def test_end_to_end_synthetic_offline_no_input_writes(self):
        old={p:p.read_bytes() for p in [self.archive,self.pfile,self.base/'sample.zbsdiff.base64']}
        out,report=self.run_fixture(self.base/'Results'/'new')
        self.assertEqual((out/'RECONSTRUCTED-TARGET-NOT-INSTALLABLE.bin').read_bytes(),b'BAD!')
        self.assertTrue(report['output_readback_verified']);self.assertFalse(report['installation_ready'])
        self.assertTrue(report['patch_applied_in_separate_staging_only']);self.assertEqual(report['network_requests'],0)
        public=(out/'Retail-Staging-Sample-to-share.json').read_text()
        self.assertNotIn(str(self.root),public);self.assertNotIn('source_path',public)
        for p,data in old.items():self.assertEqual(p.read_bytes(),data)
    def test_output_inside_game_rejected(self):
        with self.assertRaises(b.BindingError):self.run_fixture(self.folder/'new')
    def test_output_inside_lab_rejected(self):
        with self.assertRaises(b.BindingError):self.run_fixture(self.lab/'new')
    def test_existing_output_rejected(self):
        with self.assertRaises(b.BindingError):self.run_fixture(self.base)
    def test_real_pinned_patch_parses_without_claiming_reconstruction(self):
        # Public real patch structure only: source bytes are not on this machine.
        raw=base64.b64decode((Path(__file__).resolve().parents[1]/'sample.zbsdiff.base64').read_bytes(),validate=True)
        triples,_,_,info=a.parse_patch(raw,'5b933d49c411cc964fe009a18d6c2af9',33940)
        self.assertEqual(len(raw),117);self.assertEqual(info['control_triples'],1)
