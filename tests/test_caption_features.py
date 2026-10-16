import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import caption_features as caption
import ui_accessibility as uia
import observe_agent as obs

class CaptionTests(unittest.TestCase):
    def element(self,kind='Text'):
        return dict(pid=42,depth=1,control_type=kind,enabled=True,offscreen=False,password=False,label='unrecognized',markers=[])
    def test_install_directory_words_and_path_redaction(self):
        f=caption.summarize('Install Location: C:\\Users\\PRIVATE\\Battle.net')
        self.assertEqual(f['tokens'],['install','location']);self.assertTrue(f['has_path']);self.assertNotIn('PRIVATE',json.dumps(f))
    def test_unc_path_redaction(self):
        f=caption.summarize('Location: \\\\private\\installation\\SECRET');self.assertEqual(f['tokens'],['location']);self.assertTrue(f['has_path'])
    def test_email_and_urls_removed_before_word_extraction(self):
        f=caption.summarize('install@example.invalid https://private.invalid/launch file://secret/computer')
        self.assertEqual(f['tokens'],[])
    def test_unknown_words_are_never_exported(self):
        f=caption.summarize('SECRET Launch Battle.net when you start your computer.')
        self.assertTrue(f['has_unknown_words']);self.assertEqual(f['tokens'],['launch','battle.net','when','start','computer']);self.assertNotIn('SECRET',json.dumps(f))
    def test_checkbox_startup_is_not_legal_acceptance(self):
        f=caption.summarize('Launch Battle.net when you start your computer.')
        self.assertNotIn('agree',f['tokens']);self.assertNotIn('license',f['tokens'])
    def test_legal_words_retained(self):
        f=caption.summarize('I agree to the license agreement and privacy terms.')
        self.assertEqual(f['tokens'],['agree','license','agreement','privacy','terms'])
    def test_duplicates_removed(self):self.assertEqual(caption.summarize('install install INSTALL')['tokens'],['install'])
    def test_bounded_and_unknown_omitted(self):
        f=caption.summarize('x'*600);self.assertTrue(f['truncated']);self.assertEqual(f['tokens'],[])
    def test_scope_rejects_inputs_hidden_password(self):
        for kind in ('Edit','Document','Custom','ListItem','Other','Window','Hyperlink'):
            with self.assertRaises(ValueError):caption.validate(caption.summarize('install'),self.element(kind))
        for flag in ('offscreen','password'):
            e=self.element();e[flag]=True
            with self.assertRaises(ValueError):caption.validate(caption.summarize('install'),e)
    def test_extra_fields_and_unknown_words_refused(self):
        for field,value in [('raw','SECRET'),('tokens',['SECRET']),('toggle_state','SECRET'),('has_path',1)]:
            f=caption.summarize('install');f[field]=value
            with self.assertRaises(ValueError):caption.validate(f,self.element())
    def test_text_cannot_have_checkbox_state(self):
        f=caption.summarize('install');f['toggle_state']='on'
        with self.assertRaises(ValueError):caption.validate(f,self.element())
    def test_checkbox_state_is_finite(self):
        e=self.element('CheckBox');f=caption.summarize('start')
        for toggle in ('on','off','indeterminate','unavailable'):
            f['toggle_state']=toggle;caption.validate(f,e)
    def test_legacy_element_and_new_element_both_validate(self):
        e=self.element();r=dict(status='ok',elements=[e],truncated=False,errors=0,top_windows_requested=1)
        uia.validate(r,[dict(pid=42,hwnd=1)])
        e['caption_features']=caption.summarize('Install Location:');uia.validate(r,[dict(pid=42,hwnd=1)])
    def test_publication_rejects_caption_on_sensitive_element(self):
        e=self.element('Edit');e['label']='not_read';e['caption_features']=caption.summarize('install')
        r=dict(status='ok',elements=[e],truncated=False,errors=0,top_windows_requested=1)
        with self.assertRaises(ValueError):uia.validate(r,[dict(pid=42,hwnd=1)])
    def test_native_and_python_vocabulary_identical(self):
        s=Path('scripts/uia_readonly.cs').read_text();native=re.search(r'const string CaptionWords="([^"]+)";',s).group(1)
        self.assertEqual(set(native.split()),caption.WORDS)
    def test_native_caption_only_read_no_toggle_or_other_action(self):
        s=Path('scripts/uia_readonly.cs').read_text()
        self.assertIn('toggle.Current.ToggleState',s);self.assertNotIn('.Toggle(',s)
        self.assertIn('if(kind=="Text"||kind=="CheckBox")',s)
        self.assertLess(s.index('current.IsPassword'),s.index('current.Name'))
    def test_static_text_fallback_is_bounded_and_never_an_action(self):
        s=Path('scripts/uia_readonly.cs').read_text()
        block=s.split('if(kind=="Text"&&',1)[1].split('if(kind=="CheckBox")',1)[0]
        self.assertIn('ValuePattern.Pattern',block);self.assertIn('TextPattern.Pattern',block)
        self.assertIn('Caption(value.Current.Value??"")',block)
        self.assertIn('Caption(text.DocumentRange.GetText(512)??"")',block)
        for action in ('.SetValue(','.Select(','.Invoke(','.Toggle(','.SetFocus('):self.assertNotIn(action,block)
    @unittest.skipUnless(sys.platform=='win32','native caption redaction self-test')
    def test_native_real_classifier_selftest(self):
        env=obs.clean_environment(os.environ);helper,work=uia.native_helper(env)
        try:
            response=subprocess.run([str(helper),'caption-selftest'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=True)
            result=json.loads(response.stdout.decode('utf-8-sig'))
            self.assertEqual(set(result),{'path_redacted','startup_words','addresses_redacted','length_bounded'})
            self.assertTrue(all(v is True for v in result.values()))
        finally:work.cleanup()
