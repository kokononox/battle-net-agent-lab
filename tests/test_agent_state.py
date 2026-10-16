import copy
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import agent_state as state
import observe_agent as obs
import validate_report as val

class AgentStateTests(unittest.TestCase):
    def collect(self,raw,name='a.log'):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/name;p.write_bytes(raw)
            before=p.read_bytes();r=state.collect([p],{'agent':root},{})
            self.assertEqual(before,p.read_bytes());return r
    def test_empty_validates(self):self.assertEqual(state.validate(state.blank()),state.blank())
    def test_no_files(self):
        r=state.collect([],{},{});self.assertEqual(r['files_read'],0);state.validate(r)
    def test_private_text_never_copied(self):
        r=self.collect(b'[ERROR] Download failed https://host.invalid/token=SECRET private@example.invalid C:/private/user\n')
        s=json.dumps(r)
        for x in ['SECRET','host.invalid','private@example','C:/private','Download failed']:self.assertNotIn(x,s)
        self.assertEqual(r['event_counts']['failure'],1);self.assertEqual(r['event_counts']['download'],1)
    def test_line_reference_and_finite_http_code(self):
        r=self.collect(b'HTTP/1.1 403 ERROR download failed\n')
        self.assertTrue(r['events']);self.assertEqual({e['http_status'] for e in r['events']},{403})
        self.assertEqual({e['line_number'] for e in r['events']},{1})
    def test_arbitrary_numbers_not_exported(self):
        r=self.collect(b'error account 12345678 token 98765432 status=12345\n')
        self.assertEqual(r['events'][0]['http_status'],None)
        self.assertNotIn('12345678',json.dumps(r))
    def test_mentions_do_not_claim_operation_success(self):
        r=self.collect(b'patch disabled; download not started; error history\n')
        self.assertTrue(r['log_mentions_are_not_operation_proof']);self.assertNotIn('success',r)
    def test_utf16(self):
        r=self.collect('Agent starting\n'.encode('utf-16'));self.assertEqual(r['event_counts']['lifecycle'],1)
    def test_unknown_text_does_not_become_event(self):
        r=self.collect(b'SECRET arbitrary unrelated text\n');self.assertFalse(r['events']);self.assertEqual(r['lines_scanned'],1)
    def test_partial_last_line_is_not_interpreted(self):
        r=self.collect(b'Agent starting\ndownload error')
        self.assertEqual(r['partial_lines_skipped'],1);self.assertEqual(r['event_counts']['failure'],0)
    def test_giant_line_skipped(self):
        r=self.collect(b'error '+b'x'*state.MAX_LINE+b'\n');self.assertEqual(r['oversized_lines_skipped'],1);self.assertFalse(r['events'])
    def test_event_list_bounded(self):
        r=self.collect(b'error download HTTP/1.1 500\n'*1000)
        self.assertEqual(len(r['events']),state.MAX_EVENTS);self.assertTrue(r['truncated']);state.validate(r)
    def test_file_byte_cap(self):
        with patch.object(state,'MAX_FILE_BYTES',64):
            r=self.collect(b'download\n'*100);self.assertEqual(r['bytes_read'],64);self.assertTrue(r['truncated'])
    def test_total_byte_cap(self):
        with patch.object(state,'MAX_TOTAL_BYTES',64):
            r=self.collect(b'download\n'*100);self.assertEqual(r['bytes_read'],64);self.assertTrue(r['truncated'])
    def test_missing_file_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);r=state.collect([root/'missing.log'],{'agent':root},{})
            self.assertEqual(r['files_skipped'],1);self.assertEqual(r['bytes_read'],0)
    def test_binary_extension_refused(self):
        r=self.collect(b'error\n','secret.db');self.assertEqual(r['files_skipped'],1);self.assertEqual(r['bytes_read'],0)
    def test_file_outside_scope_not_read(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/'x.log';p.write_text('error\n');r=state.collect([p],{'agent':root/'other'},{})
            self.assertEqual(r['files_read'],0)
    def test_symlink_file_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/'real.log';p.write_text('error\n');link=root/'link.log'
            try:link.symlink_to(p)
            except OSError:
                with patch.object(obs,'is_reparse',return_value=True):self.assertIsNone(state.safe_category(p,{'agent':root}))
                return
            r=state.collect([link],{'agent':root},{});self.assertEqual(r['files_read'],0)
    def test_symlink_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);real=root/'real';real.mkdir();(real/'x.log').write_text('error\n');link=root/'link'
            try:link.symlink_to(real,target_is_directory=True)
            except OSError:
                with patch.object(obs,'is_reparse',side_effect=lambda p:Path(p)==real):self.assertIsNone(state.safe_category(real/'x.log',{'agent':root}))
                return
            self.assertIsNone(state.safe_category(link/'x.log',{'agent':root}))
    def test_duplicate_file_only_read_once(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/'x.log';p.write_text('error\n');r=state.collect([p,p],{'agent':root},{})
            self.assertEqual(r['files_read'],1)
    def test_deadline_stops_reading(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/'x.log';p.write_text('error\n')
            with patch.object(state.time,'monotonic',side_effect=[0,7]):r=state.collect([p],{'agent':root},{})
            self.assertEqual(r['bytes_read'],0);self.assertTrue(r['truncated'])
    def test_gui_classification_is_only_signals(self):
        gui={'accessibility':{'elements':[{'label':'installation_location','markers':['installation','location'],'offscreen':False,'password':False}]}}
        self.assertTrue(state.ui_signals(gui)['installation_options']);self.assertFalse(state.ui_signals(gui)['language'])
    def test_hidden_or_password_gui_never_classified(self):
        for f in ['offscreen','password']:
            gui={'accessibility':{'elements':[{'label':'select_language','markers':['login'],f:True}]}}
            self.assertFalse(any(state.ui_signals(gui).values()))
    def test_validator_rejects_raw_extra_field(self):
        r=state.blank();r['raw_log']='SECRET'
        with self.assertRaises(ValueError):state.validate(r)
    def test_validator_rejects_arbitrary_event_values(self):
        r=self.collect(b'error\n')
        for field,value in [('kind','SECRET'),('category','SECRET'),('severity','SECRET'),('http_status',True),('file_index',True),('line_number',0)]:
            x=copy.deepcopy(r);x['events'][0][field]=value
            with self.assertRaises(ValueError):state.validate(x)
    def test_validator_rejects_counter_and_flag_lies(self):
        for field,value in [('files_read',True),('truncated',1),('raw_text_exported',True),('log_mentions_are_not_operation_proof',False),('gui_markers_are_not_page_proof',False)]:
            r=state.blank();r[field]=value
            with self.assertRaises(ValueError):state.validate(r)
    def test_publication_checks_nested_state(self):
        r=obs.initial_report();val.validate(r);r['agent_state']['raw_text_exported']=True
        with self.assertRaises(val.ReportError):val.validate(r)
    def test_collector_has_no_network_process_or_ui_actions(self):
        s=inspect.getsource(state)
        for x in ['subprocess','urllib','requests.','os.system','InvokePattern','SelectionItemPattern','sqlite3.connect']:self.assertNotIn(x,s)
    def test_collection_integrated_before_cleanup(self):
        s=inspect.getsource(obs.observe);self.assertLess(s.index('agent_state.collect('),s.index("report['phase']='cleanup'"))
    def test_parser_line_count_bound(self):
        counts,events,lines,over,truncated=state.parse_lines('x\n'*11000,0,'agent')
        self.assertEqual(lines,10000);self.assertTrue(truncated)
    def test_parser_deadline(self):
        with patch.object(state.time,'monotonic',return_value=10):
            counts,events,lines,over,truncated=state.parse_lines('error\n',0,'agent',deadline=1)
        self.assertEqual(lines,0);self.assertTrue(truncated)
