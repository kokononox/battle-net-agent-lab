import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from test_source_binding import Fixture,BINDING
import diagnose_target as d
import source_binding as b

class DiagnosticTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.f=Fixture(Path(self.temp.name))
    def tearDown(self):self.temp.cleanup()
    def test_identical(self):
        r,_,_=d.inspect(self.f.lab);self.assertTrue(r['complete_saved_bindings_equal'])
        self.assertTrue(all(not v['mismatched_expected_fields'] for v in r['saved'].values()))
    def test_cdn_difference(self):
        self.f.meta(self.f.inv,'target_binding',{**BINDING,'cdn_config':'a'*32})
        r,_,_=d.inspect(self.f.lab)
        self.assertEqual(r['known_fields_differing_between_saved_databases'],['cdn_config'])
        self.assertEqual(r['saved']['inventory']['mismatched_expected_fields'],['cdn_config'])
    def test_consistent_but_different_target(self):
        for p in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.meta(p,'target_binding',{**BINDING,'version':'12.1.0.69933'})
        r,_,_=d.inspect(self.f.lab);self.assertTrue(r['complete_saved_bindings_equal'])
        self.assertEqual(r['saved']['plan']['mismatched_expected_fields'],['version'])
    def test_private_values_redacted(self):
        obj={**BINDING,'build_config':'C:/secret/path','private-token':'SUPERSECRET'}
        self.f.meta(self.f.ev,'target_binding',obj)
        r,_,_=d.inspect(self.f.lab);s=json.dumps(r)
        for secret in ('C:/secret/path','private-token','SUPERSECRET',str(self.f.lab)):self.assertNotIn(secret,s)
        self.assertEqual(r['other_fields_differing_count'],1)
    def test_no_network_payload_or_writes(self):
        files=[p for p in self.f.lab.rglob('*') if p.is_file()]+[self.f.archive]
        before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in files]
        original=Path.open
        def guard(p,*args,**kw):
            if p==self.f.archive:raise AssertionError('payload')
            return original(p,*args,**kw)
        with patch.object(Path,'open',guard),patch.object(socket,'socket',side_effect=AssertionError('network')):d.inspect(self.f.lab)
        self.assertEqual(before,[hashlib.sha256(p.read_bytes()).hexdigest() for p in files])
    def test_changed_reference_rejected(self):
        with self.f.plan.open('ab') as f:f.write(b'x')
        with self.assertRaisesRegex(b.BindingError,'saved_file_fingerprint_changed'):d.inspect(self.f.lab)
    def test_non_dictionary(self):
        self.f.meta(self.f.queue,'target_binding',[])
        r,_,_=d.inspect(self.f.lab);self.assertFalse(r['saved']['queue']['is_dictionary'])
    def test_missing_distinct_from_null(self):
        r=d.compare([{}, {'download_ckey':None},{},{}])
        self.assertFalse(r['complete_saved_bindings_equal'])
        self.assertEqual(r['known_fields_differing_between_saved_databases'],['download_ckey'])

if __name__=='__main__':unittest.main()
