import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import setup_visual as visual
import ui_accessibility as uia
import observe_agent as obs
import validate_report as val

class VisualTests(unittest.TestCase):
    def test_blank_validates(self):visual.validate(visual.blank())
    def test_wrong_fields_refused(self):
        r=visual.blank();r['raw']='SECRET'
        with self.assertRaises(ValueError):visual.validate(r)
    def test_refused_cannot_include_image(self):
        r=visual.blank('refused');r['image_png_base64']='SECRET'
        with self.assertRaises(ValueError):visual.validate(r)
    def test_captured_requires_valid_png_bounds(self):
        r=visual.blank('captured');r.update(width=640,height=480,image_png_base64='SECRET')
        with self.assertRaises(ValueError):visual.validate(r)
    def test_ambiguous_scope_never_launches(self):
        with patch.object(visual.subprocess,'run',side_effect=AssertionError()):
            self.assertEqual(visual.capture([])['status'],'refused')
            self.assertEqual(visual.capture([{},{}])['status'],'refused')
    def test_native_capture_has_only_window_not_desktop(self):
        s=Path('scripts/setup_visual.cs').read_text()
        for forbidden in ('CopyFromScreen','GetDesktopWindow','GetDC(IntPtr.Zero','SendInput','.Invoke(','.Select(','.Toggle(','.SetValue('):self.assertNotIn(forbidden,s)
        for required in ('PrintWindow(hwnd,dc,2)','AuthenticodeNative.Verify','ControlType.Text','ControlType.CheckBox','c.IsPassword','c.IsOffscreen','buttons==1&&changes==1&&boxes==1&&texts==2'):
            self.assertIn(required,s)
        self.assertLess(s.index('if(!Page(root,pid))'),s.index('PrintWindow(hwnd,dc,2)'))
    def test_report_checks_visual_schema(self):
        r=obs.initial_report();val.validate(r);r['setup_visual']['image_png_base64']='SECRET'
        with self.assertRaises(val.ReportError):val.validate(r)
    @unittest.skipUnless(sys.platform=='win32','native window capture denied config')
    def test_native_missing_config_refused_without_pixels(self):
        env=obs.clean_environment(os.environ);helper,work=uia.native_helper(env)
        try:
            p=subprocess.run([str(helper),'setup-visual'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=True)
            r=visual.validate(json.loads(p.stdout.decode('utf-8-sig')));self.assertEqual(r,visual.blank('refused'))
        finally:work.cleanup()
