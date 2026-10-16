import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import install_step as step
import language_step as lang
import observe_agent as obs
import ui_accessibility as uia
import validate_report as val

class InstallTests(unittest.TestCase):
    targets=[{'pid':42,'hwnd':123}]
    def result(self):
        r=step.blank(True);r.update(status='continued',helper_started=True,page_confirmed=True,continue_attempted=True,continue_returned=True);return r
    def test_default_no_action(self):
        with patch.object(step.subprocess,'run',side_effect=AssertionError()):self.assertEqual(step.run(self.targets,42,Path('setup.exe')),step.blank())
    def test_scope_refused(self):
        for targets,pid,status in (([],42,'no_targets'),(self.targets,43,'no_targets'),(self.targets*2,42,'ambiguous_window')):
            self.assertEqual(step.run(targets,pid,Path('setup.exe'),True)['status'],status)
    def test_environment_requires_both_approvals_push_first_attempt(self):
        env={'BNET_LAB_ADVANCE_LANGUAGE':'true','BNET_LAB_ADVANCE_INSTALL':'true','GITHUB_EVENT_NAME':'push','GITHUB_RUN_ATTEMPT':'1'}
        self.assertTrue(step.authorized_environment(env))
        for key,value in [('BNET_LAB_ADVANCE_LANGUAGE','false'),('BNET_LAB_ADVANCE_INSTALL','false'),('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_RUN_ATTEMPT','2')]:
            bad=dict(env);bad[key]=value;self.assertFalse(step.authorized_environment(bad))
    def test_schema_rejects_raw(self):
        r=step.blank();r['raw']='SECRET'
        with self.assertRaises(ValueError):step.validate(r)
    def test_page_confirmation_required(self):
        r=self.result();r['page_confirmed']=False
        with self.assertRaises(ValueError):step.validate(r)
    def test_helper_required(self):
        r=self.result();r['helper_started']=False
        with self.assertRaises(ValueError):step.validate(r)
    def test_unauthorized_cannot_act(self):
        r=self.result();r['authorized']=False
        with self.assertRaises(ValueError):step.validate(r)
    def test_continue_return_requires_attempt(self):
        r=self.result();r['continue_attempted']=False
        with self.assertRaises(ValueError):step.validate(r)
    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):step.decode(b'{"status":"pending","status":"continued"}')
    def test_success_does_not_mean_installed(self):
        step.validate(self.result());self.assertFalse(obs.initial_report()['interpretation']['installation_complete_proven'])
    def test_wrapper_fixed_args_no_token(self):
        response=subprocess.CompletedProcess([],0,stdout=json.dumps(self.result()).encode())
        with patch.object(step.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(step.subprocess,'run',return_value=response) as call,patch.dict(os.environ,{'GITHUB_TOKEN':'SECRET'}):
            self.assertTrue(step.run(self.targets,42,Path('setup.exe'),True)['continue_returned'])
            self.assertEqual(call.call_args.args[0],['helper.exe','advance-install']);self.assertNotIn('GITHUB_TOKEN',call.call_args.kwargs['env'])
    def test_timeout_no_retry_uncertain(self):
        with patch.object(step.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(step.subprocess,'run',side_effect=subprocess.TimeoutExpired('SECRET',12)) as call:
            r=step.run(self.targets,42,Path('setup.exe'),True);self.assertEqual(r['status'],'timeout');self.assertTrue(r['outcome_uncertain']);self.assertEqual(call.call_count,1);self.assertNotIn('SECRET',json.dumps(r))
    def test_timeout_recovers_journal(self):
        def timeout(*a,**kw):
            cfg=json.loads(kw['env']['BNET_LAB_INSTALL_CONFIG']);r=self.result();r.update(status='continue_attempted',continue_returned=False);Path(cfg['journal']).write_text(json.dumps(r));raise subprocess.TimeoutExpired('SECRET',12)
        with patch.object(step.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(step.subprocess,'run',side_effect=timeout):
            r=step.run(self.targets,42,Path('setup.exe'),True);self.assertTrue(r['journal_recovered']);self.assertTrue(r['continue_attempted']);self.assertFalse(r['continue_returned'])
    def test_report_requires_signature_and_language(self):
        r=obs.initial_report();r['install_step']=self.result()
        with self.assertRaises(val.ReportError):val.validate(r)
        r['installer']={'accepted_for_execution':True}
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_workflow_matches_both_exact_commit_gates(self):
        self.assertEqual(step.APPROVED_COMMIT,lang.APPROVED_COMMIT)
        s=Path('.github/workflows/agent-observation.yml').read_text()
        self.assertEqual(s.count(step.APPROVED_COMMIT),2)
        self.assertIn('BNET_LAB_ADVANCE_INSTALL: >-',s)
    def test_native_exact_page_signature_and_one_invoke(self):
        s=Path('scripts/install_advance.cs').read_text()
        for required in ('AuthenticodeNative.Verify(setup)','GetWindowThreadProcessId','MainModule.FileName','launch battle.net when you start your computer','count!=6||buttons!=1||changes!=1||boxes!=1||texts!=2','ControlType.Text','c.IsPassword','File.Replace','Flush(true)','Automation.Compare(button,Page('):self.assertIn(required,s)
        self.assertEqual(s.count('((InvokePattern)pattern).Invoke();'),1)
        for forbidden in ('SendInput','SendKeys','SetFocus','RootElement','GetClickablePoint','mouse_event','SetValue','.Toggle(','.Select('):self.assertNotIn(forbidden,s)
        self.assertLess(s.index('AuthenticodeNative.Verify(setup)'),s.index('((InvokePattern)pattern).Invoke();'))
        self.assertLess(s.index('r["continue_attempted"]=true'),s.index('((InvokePattern)pattern).Invoke();'))
    def test_observer_only_one_guarded_install_callback(self):
        s=Path(obs.__file__).read_text();self.assertIn('advance_install=False',s);self.assertEqual(s.count('on_visible_targets=install)'),1)
        self.assertIn('advance_install and not install_checked',s);self.assertIn('install_checked=True',s)
        self.assertIn("report['language_step']['status']=='continued' and not report['language_step']['outcome_uncertain']",s)
        self.assertIn('advance_language and not advance_install',s)
    @unittest.skipUnless(sys.platform=='win32','native install denied-config check')
    def test_native_missing_config_no_action(self):
        env=obs.clean_environment(os.environ);helper,work=uia.native_helper(env)
        try:
            env['BNET_LAB_INSTALL_CONFIG']='{}'
            p=subprocess.run([str(helper),'advance-install'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=True)
            r=step.decode(p.stdout);self.assertEqual(r['status'],'native_exception');self.assertFalse(r['continue_attempted']);self.assertFalse(r['page_confirmed'])
        finally:work.cleanup()
