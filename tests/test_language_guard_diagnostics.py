"""Guard diagnostics are finite enums; no guard or action policy is relaxed."""
import json
from pathlib import Path
import re
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import language_step as lang

class GuardDiagnosticTests(unittest.TestCase):
    def source(self):return Path('scripts/language_advance.cs').read_text()
    def test_every_native_stop_is_publishable_enum(self):
        codes=set(re.findall(r'new Stop\("([a-z_]+)"\)',self.source()))
        self.assertTrue(codes);self.assertTrue(codes<=lang.STATUSES)
        for code in codes:
            r=lang.blank(True);r.update(status=code,helper_started=True)
            self.assertEqual(lang.decode(json.dumps(r).encode()),r)
    def test_precise_page_guards_are_distinct(self):
        codes=set(re.findall(r'new Stop\("([a-z_]+)"\)',self.source()))
        self.assertTrue({'unsafe_name','name_too_long','forbidden_control','forbidden_text','language_group_missing','language_group_ambiguous','continue_missing','continue_ambiguous','page_changed'}<=codes)
    def test_raw_provider_reason_still_rejected(self):
        r=lang.blank(True);r.update(status='provider secret or raw text',helper_started=True)
        with self.assertRaises(ValueError):lang.validate(r)
    def test_checks_remain_before_actions(self):
        s=self.source()
        self.assertLess(s.index('var controls=Controls(root,pid)'),s.index('select.Select();'))
        self.assertLess(s.index('var again=Controls(root,pid)'),s.index('invoke.Invoke();'))
        self.assertIn('if(groups.Count==0)throw',s);self.assertIn('if(groups.Count!=1)throw',s)
        self.assertIn('if(buttons.Count==0)throw',s);self.assertIn('if(buttons.Count!=1)throw',s)
        self.assertEqual(s.count('select.Select();'),1);self.assertEqual(s.count('invoke.Invoke();'),1)
    def test_tree_never_prunes_subtree_by_runtime_id(self):
        s=self.source().split('static List<AutomationElement> Tree(',1)[1].split('static AutomationElement[] Controls(',1)[0]
        self.assertNotIn('GetRuntimeId()',s)
        self.assertNotIn('seen.Add',s)
        for guard in ('result.Count>=64','watch.ElapsedMilliseconds>3000','n.D>=6','count>64','stack.Count>=64','c.ProcessId!=pid'):
            self.assertIn(guard,s)
