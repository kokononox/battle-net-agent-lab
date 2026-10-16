import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import observe_agent as obs
import validate_report as val

class LabTests(unittest.TestCase):
    def test_token_environment_is_not_inherited(self):
        result=obs.clean_environment({'PATH':'system','SystemRoot':'windows','GITHUB_TOKEN':'SECRET','ACTIONS_RUNTIME_TOKEN':'SECRET','PASSWORD':'SECRET','AWS_SECRET_ACCESS_KEY':'SECRET'})
        self.assertEqual(result,{'PATH':'system','SystemRoot':'windows'})
    def test_official_https_urls_accepted(self):
        for url in (obs.SETUP_URL,'https://us.battle.net/a','https://level3.ssl.blizzard.com/b','https://blzddist1-a.akamaihd.net/c'):self.assertEqual(obs.safe_url(url),url)
    def test_untrusted_redirects_or_credentials_refused(self):
        for url in ('http://downloader.battle.net/a','https://battle.net.evil.test/a','https://user:pass@battle.net/a','https://battle.net:8080/a','https://evil.test/a'):
            with self.assertRaises(obs.LabError):obs.safe_url(url)
    def test_report_has_no_arbitrary_or_private_fields(self):
        r=obs.initial_report();r['raw_logs']='SECRET'
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_initial_report_validates(self):val.validate(obs.initial_report())
    def test_non_hosted_machine_refused_without_launching_or_network(self):
        with tempfile.TemporaryDirectory() as t,patch.object(obs.sys,'platform','linux'),patch.object(obs,'fetch_setup',side_effect=AssertionError('network forbidden')),patch.object(obs,'snapshot',side_effect=AssertionError('host touched')):
            r=obs.observe(Path(t));self.assertEqual(r['error_code'],'fresh_github_hosted_windows_required');val.validate(r)
    def test_self_hosted_windows_refused(self):
        with tempfile.TemporaryDirectory() as t,patch.object(obs.sys,'platform','win32'),patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_OS':'Windows','RUNNER_ENVIRONMENT':'self-hosted'}),patch.object(obs,'snapshot',side_effect=AssertionError('host touched')):
            self.assertEqual(obs.observe(Path(t))['error_code'],'fresh_github_hosted_windows_required')
    def test_process_commandlines_paths_env_not_exported(self):
        r=obs.safe_snapshot({'processes':[{'Name':'Agent.exe','ProcessId':123,'ParentProcessId':1,'CommandLine':'SECRET','ExecutablePath':'SECRET','Environment':'SECRET'}]},1)
        self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['processes'][0]['name'],'agent.exe')
    def test_private_destinations_redacted_public_destinations_preserved(self):
        r=obs.safe_snapshot({'processes':[{'Name':'Agent.exe','ProcessId':1}], 'connections':[{'OwningProcess':1,'RemoteAddress':'10.0.0.1','RemotePort':443,'State':'Established'},{'OwningProcess':1,'RemoteAddress':'8.8.8.8','RemotePort':443,'State':'Established'}]},1)
        self.assertEqual([c['remote_address'] for c in r['connections']],['nonpublic','8.8.8.8'])
    def test_unrelated_process_not_exported(self):
        r=obs.safe_snapshot({'processes':[{'Name':'runner.exe','ProcessId':1}], 'connections':[{'OwningProcess':1,'RemoteAddress':'8.8.8.8','RemotePort':443}]},1);self.assertFalse(r['processes']);self.assertFalse(r['connections'])
    def test_sample_size_is_bounded(self):
        r=obs.safe_snapshot({'processes':[{'Name':'Agent.exe','ProcessId':n+1} for n in range(100)]},1);self.assertEqual(len(r['processes']),24)
    def test_raw_log_content_not_exported(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.log';p.write_text('PASSWORD=SECRET\nDownload error install patch\n')
            r=obs.log_marker_counts([p]);self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['keyword_occurrences_only']['download'],1)
    def test_signature_failure_is_not_authorization(self):
        with patch('native_authenticode.read_native',return_value={'trust_status':0,'expected_blizzard_publisher':False}):
            self.assertFalse(obs.signature(Path('test.exe'),{})['accepted_for_execution'])
    def test_signature_valid_expected_publisher(self):
        with patch('native_authenticode.read_native',return_value={'trust_status':0,'expected_blizzard_publisher':True}):
            self.assertTrue(obs.signature(Path('test.exe'),{})['accepted_for_execution'])
    def test_invalid_signature_with_right_name_still_refused(self):
        with patch('native_authenticode.read_native',return_value={'trust_status':-2146869232,'expected_blizzard_publisher':False}):
            self.assertFalse(obs.signature(Path('test.exe'),{})['accepted_for_execution'])
    def test_validator_rejects_nested_secret_field(self):
        r=obs.initial_report();r['samples']=[{'elapsed_seconds':1,'processes':[{'name':'agent.exe','pid':1,'parent_pid':0,'commandline':'SECRET'}],'connections':[]}]
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_validator_refuses_changed_safety_claim(self):
        r=obs.initial_report();r['safety']['account_login_attempted']=True
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_validator_rejects_report_with_private_ip(self):
        r=obs.initial_report();r['samples']=[{'elapsed_seconds':1,'processes':[{'name':'agent.exe','pid':1,'parent_pid':0}],'connections':[{'pid':1,'remote_address':'192.168.0.1','remote_port':443,'state':'Established'}]}]
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_validator_rejects_duplicate_keys_and_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bad.json'
            for raw in ('{"a":1,"a":2}','{"a":NaN}'):
                p.write_text(raw)
                with self.assertRaises(val.ReportError):val.load(p)
    def test_marker_logging_bounded_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.log';p.write_bytes(b'download\n'*(300000))
            r=obs.log_marker_counts([p]);self.assertLessEqual(r['bytes_read'],2*1024**2);self.assertFalse(r['raw_log_content_exported'])

    def windows_env(self,root):
        return {'GITHUB_ACTIONS':'true','RUNNER_OS':'Windows','RUNNER_ENVIRONMENT':'github-hosted',
            'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':str(root),
            'ProgramData':str(root/'programdata'),'ProgramFiles(x86)':str(root/'programfiles'),
            'LOCALAPPDATA':str(root/'local'),'SystemRoot':str(root/'windows'),
            'GITHUB_TOKEN':'SECRET','ACTIONS_RUNTIME_TOKEN':'SECRET'}
    def test_signature_rejection_prevents_process_launch(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve()
            with patch.object(obs.sys,'platform','win32'),patch.dict(os.environ,self.windows_env(root)),patch.object(obs,'snapshot',return_value={'processes':[]}),patch.object(obs,'fetch_setup',return_value={'bytes':10,'sha256':'a'*64,'redirects':0}),patch.object(obs,'signature',return_value={'authenticode_valid':False,'expected_blizzard_publisher':True,'accepted_for_execution':False}),patch.object(obs.subprocess,'Popen',side_effect=AssertionError('must not execute')):
                r=obs.observe(root/'output');self.assertEqual(r['error_code'],'installer_signature_or_publisher_not_accepted');val.validate(r)
    def test_failure_after_launch_does_not_wait_in_popen_context(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();process=Mock();process.poll.return_value=0
            with patch.object(obs.sys,'platform','win32'),patch.dict(os.environ,self.windows_env(root)),patch.object(obs,'snapshot',side_effect=[{'processes':[]},RuntimeError('SECRET'),{'processes':[]}]),patch.object(obs,'fetch_setup',return_value={'bytes':10,'sha256':'a'*64,'redirects':0}),patch.object(obs,'signature',return_value={'authenticode_valid':True,'expected_blizzard_publisher':True,'accepted_for_execution':True}),patch.object(obs.subprocess,'Popen',return_value=process) as launch,patch.object(obs,'stop_observed') as stop:
                r=obs.observe(root/'output');self.assertTrue(r['cleanup_attempted']);stop.assert_called_once()
                self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('GITHUB_TOKEN',launch.call_args.kwargs['env']);process.__enter__.assert_not_called() if hasattr(process,'__enter__') else None
    def test_download_checks_declared_body_limit_before_writing(self):
        from unittest.mock import Mock
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.status=200;response.headers={'Content-Length':str(obs.MAX_SETUP+1)}
        opener=Mock();opener.open.return_value=response
        with tempfile.TemporaryDirectory() as t,patch.object(obs.urllib.request,'build_opener',return_value=opener):
            dest=Path(t)/'test.exe'
            with self.assertRaisesRegex(obs.LabError,'declared_body_limit'):obs.fetch_setup(dest)
            self.assertFalse(dest.exists());response.read.assert_not_called()
    def test_download_non_pe_refused_and_partial_removed(self):
        class Response(io.BytesIO):
            status=200
            headers={'Content-Length':'4'}
        from unittest.mock import Mock
        opener=Mock();opener.open.return_value=Response(b'HTML')
        with tempfile.TemporaryDirectory() as t,patch.object(obs.urllib.request,'build_opener',return_value=opener):
            dest=Path(t)/'test.exe'
            with self.assertRaisesRegex(obs.LabError,'not_windows_pe'):obs.fetch_setup(dest)
            self.assertFalse(dest.exists());self.assertFalse(dest.with_suffix('.part').exists())

    def test_native_signature_probe_cannot_wait_for_runner_stdin(self):
        import native_authenticode as native
        import ui_accessibility as uia
        from unittest.mock import Mock
        response=Mock(returncode=0,stdout=b'{"trust_status":0,"expected_blizzard_publisher":true}')
        with patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(native.subprocess,'run',return_value=response) as call:
            self.assertTrue(native.verify(Path('test.exe'),{})['accepted_for_execution'])
            self.assertEqual(call.call_args.kwargs['stdin'],obs.subprocess.DEVNULL)

if __name__=='__main__':unittest.main()
