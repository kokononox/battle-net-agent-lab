import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import unittest
sys.path.append(str(Path(__file__).resolve().parent.parent/'prelogin-wire-h2'))
from manager import Manager
from correlate import socket_streams
from validate import validate
class HookContract(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'),'Node required')
    def test_actual_js_32_and_64_bit_contracts(self):
        p=Path(__file__).parent
        r=subprocess.run(['node',str(p/'contract.js'),str(p/'wire_hook.js')],capture_output=True,check=True,timeout=15)
        self.assertEqual(json.loads(r.stdout)['actual_js_contract_checks'],38)
class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.m=Manager.__new__(Manager);self.m.lock=threading.Lock();self.m.inputs=[];self.m.total_bytes=0;self.m.dropped=0
        self.row={'pid':1,'sha256':'a'*64,'script_errors':0,'diagnostics':{},'observations':{},'completed_operations':0,'input_events':0,'installed_hooks':[]}
    def msg(self,e,raw=b''):self.m.message(self.row,{'type':'send','payload':e},raw)
    def pending(self,kind='recv'):
        self.msg({'kind':kind,'api':'WSARecv' if kind=='recv' else 'WSASend','order':1,'socket':'s1','operation':'o1','asynchronous':True,'completion_proven':False,'return_code':-1,'accepted_bytes':None,'declared_bytes':1000000,'complete':True,'ambiguous':False},b'ABCD' if kind=='send' else b'')
    def complete(self,**kwargs):
        e={'kind':'socket_complete','socket':'s1','operation':'o1','accepted_bytes':4,'complete':True,'ambiguous':False};e.update(kwargs);self.msg(e,b'ABCD')
    def test_pending_not_accepted(self):
        self.pending();self.assertEqual(socket_streams(self.m.inputs,'recv'),{(1,'s1'):[]})
    def test_completion_promotes_exact_event(self):
        self.pending();self.complete();self.assertEqual(len(self.m.inputs),1);self.assertEqual(socket_streams(self.m.inputs,'recv'),{(1,'s1'):[b'ABCD']});self.assertEqual(self.row['completed_operations'],1)
    def test_false_completion_still_barrier(self):
        self.pending();self.complete(complete=False);self.assertEqual(self.row['script_errors'],1);self.assertFalse(self.m.inputs[0]['completion_proven'])
    def test_wrong_socket_rejected(self):
        self.pending();self.complete(socket='s2');self.assertEqual(self.row['script_errors'],1)
    def test_wrong_operation_rejected(self):
        self.pending();self.complete(operation='o2');self.assertEqual(self.row['script_errors'],1)
    def test_duplicate_completion_error(self):
        self.pending();self.complete();self.complete();self.assertEqual(self.row['script_errors'],1)
    def test_completion_length_rejected(self):
        self.pending();self.complete(accepted_bytes=5);self.assertEqual(self.row['script_errors'],1)
    def test_send_snapshot_mismatch_rejected(self):
        self.pending('send');self.m.inputs[0]['raw']=b'WXYZ';self.complete();self.assertEqual(self.row['script_errors'],1)
    def test_ambiguous_completion_no_stream(self):
        self.pending();self.complete(ambiguous=True);self.assertEqual(socket_streams(self.m.inputs,'recv'),{})
    def test_completion_without_initial_no_evidence(self):
        self.complete();self.assertEqual(self.row['script_errors'],1);self.assertEqual(self.m.inputs,[])
    def test_allowlisted_diagnostic(self):
        self.msg({'kind':'read_error','api':'recv','phase':'leave','reason':'bounded'});self.assertEqual(self.row['diagnostics'],{'recv|leave|bounded':1})
    def test_private_exception_not_exported(self):
        self.msg({'kind':'read_error','api':'PRIVATE','phase':'SECRET','reason':'ADDRESS'});self.assertEqual(self.row['diagnostics'],{'other|other|other':1})
    def test_census_is_not_completion(self):
        self.pending();self.msg({'kind':'probe','api':'GetQueuedCompletionStatus','phase':'completion_call','state':'true'})
        self.assertFalse(self.m.inputs[0]['completion_proven'])
        self.assertEqual(self.row['observations'],{'GetQueuedCompletionStatus|completion_call|true':1})
    def test_ready_bitness(self):
        self.msg({'kind':'ready','pointer_bits':32});self.assertEqual(self.row['pointer_bits'],32)
    def test_completion_budget_keeps_barrier(self):
        self.pending();self.m.total_bytes=16*1024*1024;self.complete();self.assertEqual(self.m.dropped,1);self.assertFalse(self.m.inputs[0]['completion_proven'])
    def test_immediate_without_query_still_barrier(self):
        self.pending();self.m.inputs[0]['immediate_completion']=True
        self.assertEqual(socket_streams(self.m.inputs,'recv'),{(1,'s1'):[]})
    def test_no_normalization_without_completion(self):
        self.pending();self.m.inputs[0].update(accepted_bytes=4,raw=b'ABCD',return_code=0);self.assertEqual(socket_streams(self.m.inputs,'recv'),{(1,'s1'):[]})
class StaticScope(unittest.TestCase):
    def test_no_product_launch_entrypoint(self):
        s=Path(__file__).with_name('fixture_only.py').read_text();self.assertNotIn('fetch_setup',s);self.assertNotIn('advance_install',s);self.assertNotIn('observe_agent',s)
    def test_no_active_completion_query_in_observer(self):
        s=Path(__file__).with_name('wire_hook.js').read_text();self.assertNotIn('NativeFunction',s);self.assertNotIn('.writeByteArray',s);self.assertNotIn('retval.replace',s)
if __name__=='__main__':unittest.main()
