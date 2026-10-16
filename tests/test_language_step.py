import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import language_step as lang
import ui_accessibility as uia
import observe_agent as obs
import validate_report as val

class LanguageTests(unittest.TestCase):
    targets=[{'pid':42,'hwnd':123}]
    def result(self):
        r=lang.blank(True);r.update(status='continued',helper_started=True,selection_already_set=True,selection_confirmed=True,continue_attempted=True,continue_returned=True);return r
    def test_default_no_action(self):
        with patch.object(lang.subprocess,'run',side_effect=AssertionError()):self.assertEqual(lang.run(self.targets,42,Path('setup.exe')),lang.blank())
    def test_no_target_refused(self):self.assertEqual(lang.run([],42,Path('setup.exe'),True)['status'],'no_targets')
    def test_foreign_pid_refused(self):self.assertEqual(lang.run(self.targets,43,Path('setup.exe'),True)['status'],'no_targets')
    def test_ambiguous_refused(self):self.assertEqual(lang.run(self.targets*2,42,Path('setup.exe'),True)['status'],'ambiguous_window')
    def test_environment_requires_push_and_first_attempt(self):
        env={'BNET_LAB_ADVANCE_LANGUAGE':'true','GITHUB_EVENT_NAME':'push','GITHUB_RUN_ATTEMPT':'1'};self.assertTrue(lang.authorized_environment(env))
        for k,v in [('BNET_LAB_ADVANCE_LANGUAGE','false'),('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_RUN_ATTEMPT','2')]:
            bad=dict(env);bad[k]=v;self.assertFalse(lang.authorized_environment(bad))
    def test_schema_rejects_raw(self):
        r=lang.blank();r['raw']='SECRET'
        with self.assertRaises(ValueError):lang.validate(r)
    def test_confirmation_required(self):
        r=self.result();r['selection_confirmed']=False
        with self.assertRaises(ValueError):lang.validate(r)
    def test_unauthorized_cannot_act(self):
        r=self.result();r['authorized']=False
        with self.assertRaises(ValueError):lang.validate(r)
    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):lang.decode(b'{"status":"pending","status":"pending"}')
    def test_validated_success(self):self.assertEqual(lang.validate(self.result())['status'],'continued')
    def test_wrapper_only_two_fixed_arguments(self):
        response=subprocess.CompletedProcess([],0,stdout=json.dumps(self.result()).encode())
        with patch.object(lang.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(lang.subprocess,'run',return_value=response) as call,patch.dict(os.environ,{'GITHUB_TOKEN':'SECRET'}):
            r=lang.run(self.targets,42,Path('setup.exe'),True);self.assertTrue(r['continue_returned'])
            self.assertEqual(call.call_args.args[0],['helper.exe','advance-language']);self.assertNotIn('GITHUB_TOKEN',call.call_args.kwargs['env']);self.assertEqual(call.call_args.kwargs['timeout'],12)
    def test_timeout_is_uncertain_without_journal(self):
        with patch.object(lang.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(lang.subprocess,'run',side_effect=subprocess.TimeoutExpired('SECRET',12)) as call:
            r=lang.run(self.targets,42,Path('setup.exe'),True);self.assertEqual(r['status'],'timeout');self.assertTrue(r['outcome_uncertain']);self.assertEqual(call.call_count,1);self.assertNotIn('SECRET',json.dumps(r))
    def test_timeout_recovers_preinvoke_journal(self):
        def timeout(*a,**kw):
            cfg=json.loads(kw['env']['BNET_LAB_LANGUAGE_CONFIG']);r=self.result();r.update(status='continue_attempted',continue_returned=False);Path(cfg['journal']).write_text(json.dumps(r));raise subprocess.TimeoutExpired('SECRET',12)
        with patch.object(lang.sys,'platform','win32'),patch.object(uia,'_HELPER',(Path('helper.exe'),None)),patch.object(lang.subprocess,'run',side_effect=timeout):
            r=lang.run(self.targets,42,Path('setup.exe'),True);self.assertTrue(r['journal_recovered']);self.assertTrue(r['continue_attempted']);self.assertFalse(r['continue_returned'])
    def test_publication_requires_verified_installer(self):
        r=obs.initial_report();r['language_step']=self.result()
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_workflow_one_exact_commit_only(self):
        s=Path('.github/workflows/agent-observation.yml').read_text();self.assertIn(lang.APPROVED_COMMIT,s);self.assertIn("github.event_name == 'push'",s);self.assertIn('github.run_attempt == 1',s)
    def test_workflow_expression_uses_folded_yaml_scalar(self):
        # No PyYAML dependency on the hosted runner. Mandatory regression guard
        # for the exact colon-containing scalar; full YAML parse also run locally.
        lines=Path('.github/workflows/agent-observation.yml').read_text().splitlines()
        indices=[i for i,line in enumerate(lines) if line.strip().startswith('BNET_LAB_ADVANCE_LANGUAGE:')]
        self.assertEqual(len(indices),1)
        i=indices[0];self.assertEqual(lines[i].strip(),'BNET_LAB_ADVANCE_LANGUAGE: >-')
        self.assertTrue(lines[i+1].startswith('            ${{ '))
        self.assertTrue(lines[i+1].endswith(' }}'))
        self.assertIn(lang.APPROVED_COMMIT,lines[i+1])
        self.assertIn('github.run_attempt == 1',lines[i+1])
    def test_action_source_has_only_select_and_invoke_no_fallbacks(self):
        s=Path('scripts/language_advance.cs').read_text();self.assertEqual(s.count('select.Select();'),1);self.assertEqual(s.count('invoke.Invoke();'),1)
        for term in ('SendInput','SendKeys','SetFocus','RootElement','GetClickablePoint','mouse_event','SetValue'):self.assertNotIn(term,s)
        for term in ('select a language','english (us)','battle.net setup','continue','GetWindowThreadProcessId','MainModule.FileName','IsSelected','File.Replace','Flush(true)'):self.assertIn(term,s)
    def test_observer_default_keeps_read_only(self):
        s=Path(obs.__file__).read_text();self.assertIn('advance_language=False',s);self.assertEqual(s.count('on_visible_targets=advance)'),1)
        self.assertLess(s.index("if not report['installer']['accepted_for_execution']"),s.index('on_visible_targets=advance'))
    @unittest.skipUnless(sys.platform=='win32','native language helper denied-scope check')
    def test_actual_windows_denied_config_has_no_action(self):
        env=obs.clean_environment(os.environ)
        helper,work=uia.native_helper(env)
        try:
            env['BNET_LAB_LANGUAGE_CONFIG']='{}'
            response=subprocess.run([str(helper),'advance-language'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=True)
            r=lang.decode(response.stdout);self.assertEqual(r['status'],'native_exception');self.assertFalse(r['selection_attempted']);self.assertFalse(r['continue_attempted'])
        finally:work.cleanup()
