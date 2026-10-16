import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_authenticode as native
import ui_accessibility as uia
import observe_agent as obs
import validate_report as val

class NativeSignatureTests(unittest.TestCase):
    def test_zero_and_verified_publisher_required(self):
        for status,publisher,accepted in ((0,True,True),(0,False,False),(-2146762496,False,False),(1,False,False)):
            with patch.object(native,'read_native',return_value={'trust_status':status,'expected_blizzard_publisher':publisher}):
                self.assertEqual(native.verify(Path('Blizzard Entertainment.exe'),{})['accepted_for_execution'],accepted)
    def test_nonzero_warning_never_counts_as_success(self):
        with patch.object(native,'read_native',return_value={'trust_status':1,'expected_blizzard_publisher':False}):
            self.assertFalse(native.verify(Path('file.exe'),{})['authenticode_valid'])
    def test_inconsistent_publisher_evidence_refused(self):
        with patch.object(native,'read_native',return_value={'trust_status':-1,'expected_blizzard_publisher':True}):
            with self.assertRaises(native.NativeSignatureError):native.verify(Path('file.exe'),{})
    def test_wrong_types_or_extra_fields_rejected(self):
        for r in ({'trust_status':True,'expected_blizzard_publisher':True},{'trust_status':0,'expected_blizzard_publisher':'true'},
                  {'trust_status':0,'expected_blizzard_publisher':True,'raw_subject':'SECRET'},{'trust_status':0}):
            with patch.object(native,'read_native',return_value=r):
                with self.assertRaises(native.NativeSignatureError):native.verify(Path('file.exe'),{})
    def test_subprocess_stdin_environment_deadline(self):
        result=Mock(returncode=0,stdout=b'{"trust_status":0,"expected_blizzard_publisher":true}')
        with patch.object(uia,'_HELPER',(Path('native-helper.exe'),None)),patch.object(native.subprocess,'run',return_value=result) as run:
            native.verify(Path('file.exe'),{'SystemRoot':'C:/Windows','GITHUB_TOKEN':'SECRET','ACTIONS_RUNTIME_TOKEN':'SECRET'})
            kw=run.call_args.kwargs;self.assertEqual(kw['stdin'],subprocess.DEVNULL);self.assertEqual(kw['timeout'],60)
            self.assertEqual(kw['stderr'],subprocess.DEVNULL);self.assertNotIn('GITHUB_TOKEN',kw['env']);self.assertNotIn('ACTIONS_RUNTIME_TOKEN',kw['env'])
            self.assertEqual(run.call_args.args[0][-1],'signature');self.assertNotIn('-Command',run.call_args.args[0])
    def test_failure_and_bad_json_never_authorize(self):
        for rc,raw in ((1,b'SECRET'),(0,b'SECRET'),(0,b'x'*4097),(0,b'{"trust_status":0,"trust_status":0,"expected_blizzard_publisher":true}'),(0,b'{"trust_status":NaN,"expected_blizzard_publisher":false}')):
            with patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(native.subprocess,'run',return_value=Mock(returncode=rc,stdout=raw)):
                with self.assertRaises(native.NativeSignatureError) as caught:native.verify(Path('file.exe'),{})
                self.assertNotIn('SECRET',str(caught.exception))
    def test_timeout_remains_fatal(self):
        with patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(native.subprocess,'run',side_effect=subprocess.TimeoutExpired('SECRET',60)):
            with self.assertRaises(subprocess.TimeoutExpired):obs.signature(Path('file.exe'),{})
    def test_publication_validator_checks_native_status(self):
        r=obs.initial_report();r['installer']={'bytes':10,'sha256':'a'*64,'redirects':0,'authenticode_valid':True,'expected_blizzard_publisher':True,'accepted_for_execution':True,'winverifytrust_status':0};val.validate(r)
        r['installer']['winverifytrust_status']=1
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_native_uses_verified_signer_leaf_not_file_strings(self):
        s=Path(native.__file__).with_name('authenticode_native.cs').read_text()
        self.assertIn('WTHelperProvDataFromStateData(state)',s);self.assertIn('WTHelperGetProvSignerFromChain(provider,0,false,0)',s)
        self.assertIn('CertGetNameStringW(certificate.certificate,4,0',s)
        self.assertIn('if(status==0) publisher=ExpectedPublisher(data.stateData)',s)
        self.assertNotIn('CreateFromSignedFile',s);self.assertNotIn('GetFileName',s)
    def test_revocation_no_ui_and_state_cleanup_preserved(self):
        s=Path(native.__file__).with_name('authenticode_native.cs').read_text()
        for fragment in ('uiChoice=2','revocationChecks=1','providerFlags=0x2080','data.stateAction=2','new IntPtr(-1)','FileShare.Read'):
            self.assertIn(fragment,s)
        self.assertNotIn('WTD_REVOCATION_CHECK_NONE',s);self.assertNotIn('WTD_CACHE_ONLY_URL_RETRIEVAL',s)
        self.assertNotIn('X509Store',s);self.assertNotIn('Process.Start',s)
    def test_original_publisher_allowlist_unchanged(self):
        s=Path(native.__file__).with_name('authenticode_native.cs').read_text()
        for name in obs.PUBLISHERS:self.assertIn('"'+name+'"',s)
    def test_signature_path_never_calls_powershell(self):
        import inspect
        self.assertNotIn('powershell(',inspect.getsource(obs.signature))
        self.assertNotIn('Get-AuthenticodeSignature',inspect.getsource(native))

@unittest.skipUnless(sys.platform=='win32','native Windows Authenticode integration')
class NativeSignatureWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous=uia._HELPER;cls.environment=obs.clean_environment(os.environ)
        cls.helper=uia.native_helper(cls.environment);uia._HELPER=cls.helper
    @classmethod
    def tearDownClass(cls):
        uia._HELPER=cls.previous;cls.helper[1].cleanup()
    def test_real_abi_layout(self):
        response=subprocess.run([str(self.helper[0]),'signature-abi'],env=self.environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12)
        self.assertEqual(response.returncode,0);r=json.loads(response.stdout.decode('utf-8-sig'))
        self.assertIn(r['pointer_bytes'],(4,8));expected=(88,32,64,48) if r['pointer_bytes']==8 else (52,16,44,36)
        self.assertEqual(tuple(r[k] for k in ('trust_data_bytes','file_info_bytes','signer_bytes','certificate_prefix_bytes')),expected)
    def test_real_unsigned_helper_rejected(self):
        r=native.verify(self.helper[0],self.environment)
        self.assertFalse(r['authenticode_valid']);self.assertFalse(r['expected_blizzard_publisher']);self.assertFalse(r['accepted_for_execution'])
        self.assertNotEqual(r['winverifytrust_status'],0)
    def test_real_fake_blizzard_filename_and_text_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            file=Path(t)/'Blizzard Entertainment, Inc..exe';file.write_bytes(b'MZ'+b'Blizzard Entertainment, Inc.'*40)
            r=native.verify(file,self.environment);self.assertFalse(r['authenticode_valid']);self.assertFalse(r['expected_blizzard_publisher']);self.assertFalse(r['accepted_for_execution'])
