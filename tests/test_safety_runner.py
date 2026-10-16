import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import run_safety_tests as runner
import ui_accessibility as uia
import validate_report as val

class SafetyRunnerTests(unittest.TestCase):
    def make_case(self,error=None):
        def execute():
            if error:raise error
        return unittest.FunctionTestCase(execute)
    def test_native_timeout_is_failure_and_safe_report(self):
        with tempfile.TemporaryDirectory() as t:
            out=Path(t);summary=runner.run_suite(unittest.TestSuite([self.make_case(subprocess.TimeoutExpired('SECRET command',12))]),out)
            self.assertEqual(summary['result'],'failed');self.assertEqual(summary['failures'][0]['error_kind'],'TimeoutExpired')
            text=(out/'agent-observation-to-share.json').read_text();self.assertNotIn('SECRET',text)
            report=val.load(out/'agent-observation-to-share.json');self.assertFalse(report['installer']);self.assertEqual(report['phase'],'safety_tests')
    def test_success_does_not_fake_bootstrap_report(self):
        with tempfile.TemporaryDirectory() as t:
            out=Path(t);summary=runner.run_suite(unittest.TestSuite([self.make_case()]),out)
            self.assertEqual(summary['result'],'passed');self.assertFalse((out/'agent-observation-to-share.json').exists())
    def test_toolchain_error_has_only_known_code(self):
        with tempfile.TemporaryDirectory() as t:
            summary=runner.run_suite(unittest.TestSuite([self.make_case(uia.ToolchainError('uia_compile_timeout'))]),Path(t))
            self.assertEqual(summary['failures'][0]['toolchain_code'],'uia_compile_timeout')
    def test_summary_refuses_raw_error(self):
        with tempfile.TemporaryDirectory() as t:
            s=runner.run_suite(unittest.TestSuite([self.make_case()]),Path(t));s['raw_error']='SECRET'
            with self.assertRaises(ValueError):runner.validate_summary(s)
    def test_failure_details_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            s=runner.run_suite(unittest.TestSuite([self.make_case(AssertionError('SECRET')) for _ in range(20)]),Path(t))
            self.assertEqual(s['failure_count'],20);self.assertEqual(len(s['failures']),16);self.assertTrue(s['failure_list_truncated'])
    def test_native_compile_timeout_remains_blocking(self):
        with patch.object(Path,'is_file',return_value=True),patch.object(uia.subprocess,'run',side_effect=subprocess.TimeoutExpired('SECRET',30)):
            with self.assertRaises(uia.ToolchainError) as caught:uia.native_helper({})
            self.assertEqual(caught.exception.code,'uia_compile_timeout')
    def test_native_missing_compiler_remains_blocking(self):
        with patch.object(Path,'is_file',return_value=False):
            with self.assertRaises(uia.ToolchainError) as caught:uia.native_helper({})
            self.assertEqual(caught.exception.code,'uia_compiler_missing')
    def test_smoke_runtime_failure_is_not_accepted(self):
        with patch.object(uia,'launch',side_effect=subprocess.TimeoutExpired('SECRET',12)):
            with self.assertRaises(uia.ToolchainError) as caught:uia.smoke_check()
            self.assertEqual(caught.exception.code,'uia_runtime_timeout')
    def test_smoke_invalid_output_is_not_accepted(self):
        with patch.object(uia,'launch',return_value=Mock(returncode=0,stdout=b'SECRET')):
            with self.assertRaises(uia.ToolchainError) as caught:uia.smoke_check()
            self.assertEqual(caught.exception.code,'uia_runtime_output_rejected')
    def test_compiler_and_helper_no_network_or_powershell(self):
        s=Path(uia.__file__).read_text()
        self.assertNotIn("'-Command'",s);self.assertNotIn("'-EncodedCommand'",s)
        self.assertNotIn('urllib',s);self.assertNotIn('requests.',s)
        self.assertIn('timeout=30',s);self.assertIn('timeout=12',s)
