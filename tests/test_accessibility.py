import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import ui_accessibility as uia
import validate_report as val
import test_gui

class AccessibilityTests(unittest.TestCase):
    def setUp(self):
        self.helper_patch=patch.object(uia,'_HELPER',(Path('UiaReadOnly.exe'),None));self.helper_patch.start();self.addCleanup(self.helper_patch.stop)
    def targets(self):return [{'hwnd':123,'pid':42}]
    def report(self):
        return {'status':'ok','top_windows_requested':1,'errors':0,'truncated':False,'elements':[
            {'pid':42,'depth':0,'control_type':'Window','enabled':True,'offscreen':False,'password':False,
             'label':'battle_net_setup','markers':[]},
            {'pid':42,'depth':1,'control_type':'Button','enabled':True,'offscreen':False,'password':False,
             'label':'continue','markers':[]}]}
    def response(self,r=None,raw=None,returncode=0):
        return Mock(returncode=returncode,stdout=raw if raw is not None else json.dumps(r or self.report()).encode())
    def mocked_probe(self,response=None,exception=None):
        return patch.object(uia.subprocess,'run',return_value=response or self.response(),side_effect=exception)
    def test_known_safe_tree_validates(self):uia.validate(self.report(),self.targets())
    def test_foreign_process_refused(self):
        r=self.report();r['elements'][0]['pid']=900
        with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_raw_fields_refused(self):
        for f in ('name','value','automation_id','class_name','path','screenshot','raw_error'):
            r=self.report();r['elements'][0][f]='SECRET'
            with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_unknown_labels_markers_refused(self):
        for f,x in [('label','SECRET'),('markers',['SECRET'])]:
            r=self.report();r['elements'][0][f]=x
            with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_sensitive_types_never_have_name(self):
        for kind in ('Edit','Document','Custom','ListItem','Other'):
            r=self.report();r['elements'][0]['control_type']=kind
            with self.assertRaises(ValueError):uia.validate(r,self.targets())
            r['elements'][0].update(label='not_read',markers=[]);uia.validate(r,self.targets())
    def test_password_hidden_names_refused(self):
        for f in ('password','offscreen'):
            r=self.report();r['elements'][0][f]=True
            with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_tree_bounds(self):
        r=self.report();r['elements']=[r['elements'][0]]*65
        with self.assertRaises(ValueError):uia.validate(r,self.targets())
        r=self.report();r['elements'][0]['depth']=7
        with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_non_ok_cannot_smuggle_elements(self):
        r=self.report();r['status']='timeout'
        with self.assertRaises(ValueError):uia.validate(r,self.targets())
    def test_no_targets_never_starts_process(self):
        with patch.object(uia.subprocess,'run',side_effect=AssertionError('forbidden')):
            self.assertEqual(uia.inspect([])['status'],'no_targets')
    def test_bad_inputs_never_start_process(self):
        for targets in ([{'hwnd':0,'pid':42}],[{'hwnd':True,'pid':42}],[{'hwnd':1,'pid':0}],self.targets()*9,[{'hwnd':1,'pid':42,'raw':'SECRET'}]):
            with patch.object(uia.subprocess,'run',side_effect=AssertionError('forbidden')):
                with self.assertRaises(ValueError):uia.inspect(targets)
    def test_env_timeout_stdin_readonly_execution(self):
        with patch.object(uia.sys,'platform','win32'),patch.dict(os.environ,{'GITHUB_TOKEN':'SECRET','ACTIONS_RUNTIME_TOKEN':'SECRET'}),self.mocked_probe() as call:
            self.assertEqual(uia.inspect(self.targets())['status'],'ok')
            kw=call.call_args.kwargs
            self.assertNotIn('GITHUB_TOKEN',kw['env']);self.assertNotIn('ACTIONS_RUNTIME_TOKEN',kw['env'])
            self.assertEqual(kw['timeout'],12);self.assertEqual(kw['stdin'],subprocess.DEVNULL);self.assertEqual(kw['stderr'],subprocess.DEVNULL)
            self.assertEqual(len(call.call_args.args[0]),1);self.assertNotIn('powershell',call.call_args.args[0][0].lower())
    def test_timeout_exports_no_partial_stdout_or_message(self):
        err=subprocess.TimeoutExpired('SECRET',12,output=b'SECRET')
        with patch.object(uia.sys,'platform','win32'),self.mocked_probe(exception=err):
            r=uia.inspect(self.targets());self.assertEqual(r['status'],'timeout');self.assertNotIn('SECRET',json.dumps(r))
    def test_nonzero_process_exports_no_raw_data(self):
        with patch.object(uia.sys,'platform','win32'),self.mocked_probe(self.response(raw=b'SECRET',returncode=1)):
            self.assertEqual(uia.inspect(self.targets()),uia.blank('probe_failed',1))
    def test_large_or_invalid_output_refused(self):
        for raw in (b'x'*(uia.MAX_OUTPUT+1),b'SECRET',b'{"status":NaN}',b'{"status":1,"status":2}'):
            with patch.object(uia.sys,'platform','win32'),self.mocked_probe(self.response(raw=raw)):
                self.assertEqual(uia.inspect(self.targets())['status'],'output_rejected')
    def test_nested_raw_data_rejected_in_wrapper(self):
        r=self.report();r['elements'][0]['raw']='SECRET'
        with patch.object(uia.sys,'platform','win32'),self.mocked_probe(self.response(r)):
            self.assertEqual(uia.inspect(self.targets())['status'],'output_rejected')
    def test_publication_validator_checks_pid_ownership(self):
        g=test_gui.GuiTests().fixture();g['accessibility']=self.report();val.validate_gui(g)
        g['accessibility']['elements'][0]['pid']=900
        with self.assertRaises(val.ReportError):val.validate_gui(g)
    def test_publication_validator_rejects_private_name(self):
        g=test_gui.GuiTests().fixture();g['accessibility']=self.report();g['accessibility']['elements'][0]['name']='SECRET'
        with self.assertRaises(val.ReportError):val.validate_gui(g)
    def test_script_only_reads_named_properties_tree(self):
        s=Path(uia.__file__).with_name('uia_readonly.cs').read_text()
        for forbidden in ('.Invoke(','.Select(','.SetValue(','.SetFocus(','.Expand(','SendInput','GetClickablePoint'):
            self.assertNotIn(forbidden,s)
        self.assertIn('current.IsPassword',s);self.assertIn('current.IsOffscreen',s)
        self.assertIn('current.ProcessId!=pid',s)
        self.assertLess(s.index('current.IsPassword'),s.index('current.Name'))
        self.assertIn('FromHandle',s);self.assertNotIn('RootElement',s)
        # Bounded read fallback is explicitly limited to already scoped static Text.
        # Input/document/password/hidden values are still forbidden, as are actions.
        self.assertIn('if(kind=="Text"&&',s)
        self.assertEqual(s.count('.GetText(512)'),1)
        self.assertNotIn('.GetText(-1)',s)
        self.assertLess(s.index('if(kind=="Text"&&'),s.index('value.Current.Value'))
        self.assertLess(s.index('current.IsPassword'),s.index('value.Current.Value'))
    @unittest.skipUnless(sys.platform=='win32','native Windows UIA empty-target smoke test')
    def test_actual_windows_helper_with_no_targets(self):
        # Deliberately undo the transport mock: this test must really compile/run on Windows.
        with patch.object(uia,'_HELPER',None):
            result=uia.smoke_check();self.assertEqual(result['status'],'ok');self.assertEqual(result['elements'],[])
