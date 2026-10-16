import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_gui as gui
import observe_agent as obs
import validate_report as val

class GuiTests(unittest.TestCase):
    def fixture(self):
        return {'elapsed_seconds':5.0,'observer_session_id':1,'process_sessions':[{'pid':42,'session_id':1}],
                'window_station_visible':True,'input_desktop_accessible':True,'input_desktop_error':None,
                'windows':[{'class':'dialog','visible':True,'enabled':True,'label':'battle_net_setup','markers':[],
                'controls':[{'class':'button','visible':True,'enabled':True,'label':'ok','markers':[]}]}],
                'enumeration_truncated':False,'probe_errors':0,
                'accessibility':{'status':'no_targets','elements':[],'truncated':False,'errors':0,'top_windows_requested':0}}
    def test_unknown_text_not_exported(self):
        x=gui.safe_text('private@example.invalid /private/local/file SECRET','static',True)
        self.assertEqual(x,{'label':'unrecognized','markers':[]})
    def test_hidden_and_input_or_unknown_classes_not_read(self):
        for k in ('edit','rich_edit','other','chromium','link','progress','combo_list'):
            self.assertEqual(gui.safe_text('SECRET login',k,True),{'label':'not_read','markers':[]})
        self.assertEqual(gui.safe_text('Install','button',False),{'label':'not_read','markers':[]})
    def test_known_labels_and_fixed_markers(self):
        self.assertEqual(gui.safe_text(' &OK ','button',True)['label'],'ok')
        self.assertEqual(gui.safe_text('English (US)','combobox',True)['label'],'english_us')
        self.assertEqual(gui.safe_text('Please sign-in: SECRET license','static',True),{'label':'unrecognized','markers':['license','sign_in']})
    def test_class_mapping_fixed(self):
        self.assertEqual(gui.classify_class('#32770'),'dialog')
        self.assertEqual(gui.classify_class('Chrome_WidgetWin_1'),'chromium')
        self.assertEqual(gui.classify_class('SECRET'),'other')
    def test_gui_validates(self):val.validate_gui(self.fixture())
    def test_no_raw_caption_or_screenshot_field(self):
        for key in ('text','title','screenshot','path','account'):
            x=self.fixture();x['windows'][0][key]='SECRET'
            with self.assertRaises(val.ReportError):val.validate_gui(x)
    def test_no_arbitrary_label_or_marker(self):
        for key,value in [('label','SECRET'),('markers',['SECRET'])]:
            x=self.fixture();x['windows'][0][key]=value
            with self.assertRaises(val.ReportError):val.validate_gui(x)
    def test_edit_or_hidden_label_forbidden(self):
        for kind,visible in [('edit',True),('rich_edit',True),('other',True),('chromium',True),('button',False)]:
            x=self.fixture();x['windows'][0]['controls'][0].update({'class':kind,'visible':visible})
            with self.assertRaises(val.ReportError):val.validate_gui(x)
    def test_window_and_control_bounds(self):
        x=self.fixture();x['windows']*=9
        with self.assertRaises(val.ReportError):val.validate_gui(x)
        x=self.fixture();x['windows'][0]['controls']*=33
        with self.assertRaises(val.ReportError):val.validate_gui(x)
    def test_provenance_and_short_run(self):
        x=obs.initial_report();x.update(source_commit='a'*40,run_id='123',run_attempt='1',gui_observations=[self.fixture()]);x['limits']['observation_seconds']=45
        val.validate(x)
        x['source_commit']='SECRET'
        with self.assertRaises(val.ReportError):val.validate(x)
    def test_observation_limits_fail_closed(self):
        for n in (0,29,151,True):
            with self.assertRaises(obs.LabError):obs.observe(Path('unused'),n)
    def test_nonwindows_native_probe_refused(self):
        from unittest.mock import patch
        with patch.object(gui.sys,'platform','linux'):
            with self.assertRaises(OSError):gui.inspect({1},1)
    def test_native_inspection_has_no_mutation_apis(self):
        source=(Path(gui.__file__)).read_text()
        for api in ('SendInput','PostMessage','SetWindowText','mouse_event','keybd_event','BM_CLICK','SetForegroundWindow'):
            self.assertNotIn(api,source)
        self.assertIn('0x000D',source)
