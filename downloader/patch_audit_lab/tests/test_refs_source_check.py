import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib
from test_source_binding import Fixture,BINDING
from test_patch_audit import fake_blte
import refs_source_check as r
import patch_audit as a
import source_binding as b


def mkoption(ek,ds):return a.PatchOption('20'*16,4,ek,ds,'40'*16,100,0)

class DecodeTests(unittest.TestCase):
    def test_chunked_n_and_z(self):
        raw,ek,ck,ds=fake_blte();data,proof=r.decode_source(raw,ek,ds)
        self.assertEqual(data,b'abcd');self.assertEqual(proof['derived_source_ckey'],ck)
        self.assertTrue(proof['full_source_ekey_verified']);self.assertTrue(proof['chunk_integrity_verified'])
        self.assertFalse(proof['independent_expected_source_ckey_available'])
    def test_single_n(self):
        raw=b'BLTE'+bytes(4)+b'Nabc';data,p=r.decode_source(raw,a.md5(raw),3)
        self.assertEqual(data,b'abc');self.assertTrue(p['single_chunk_full_object_hash_verified'])
    def test_single_z(self):
        raw=b'BLTE'+bytes(4)+b'Z'+zlib.compress(b'abc')
        self.assertEqual(r.decode_source(raw,a.md5(raw),3)[0],b'abc')
    def test_wrong_full_ekey(self):
        raw,ek,ck,ds=fake_blte()
        with self.assertRaisesRegex(a.AuditError,'ekey'):r.decode_source(raw,'00'*16,ds)
    def test_same_prefix_not_full_key_proof(self):
        raw,ek,ck,ds=fake_blte();wrong=ek[:18]+('0' if ek[18]!='0' else '1')+ek[19:]
        with self.assertRaisesRegex(a.AuditError,'ekey'):r.decode_source(raw,wrong,ds)
    def test_corrupt_chunk(self):
        raw,ek,ck,ds=fake_blte();raw=raw[:-1]+bytes([raw[-1]^1])
        with self.assertRaisesRegex(a.AuditError,'checksum'):r.decode_source(raw,ek,ds)
    def test_wrong_decoded_size(self):
        raw,ek,ck,ds=fake_blte()
        with self.assertRaises(a.AuditError):r.decode_source(raw,ek,ds+1)
    def test_trailing_data_rejected(self):
        raw,ek,ck,ds=fake_blte()
        with self.assertRaises(a.AuditError):r.decode_source(raw+b'x',ek,ds)
    def test_encrypted_unsupported(self):
        raw=b'BLTE'+bytes(4)+b'Eabc'
        with self.assertRaisesRegex(a.AuditError,'unsupported'):r.decode_source(raw,a.md5(raw),3)
    def test_bounded_inflate(self):
        raw=b'BLTE'+bytes(4)+b'Z'+zlib.compress(b'x'*10000)
        with self.assertRaises(a.AuditError):r.decode_source(raw,a.md5(raw),3)
    def test_truncations(self):
        raw,ek,ck,ds=fake_blte()
        for size in range(len(raw)):
            with self.subTest(size=size),self.assertRaises(a.AuditError):r.decode_source(raw[:size],ek,ds)
    def test_unsupported_flags(self):
        raw,ek,ck,ds=fake_blte();raw=raw[:8]+b'\x00'+raw[9:]
        with self.assertRaises(a.AuditError):r.decode_source(raw,a.md5(raw[:60]),ds)

class RefsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.raw,self.ek,self.ck,self.ds=fake_blte();self.option=mkoption(self.ek,self.ds)
        self.f=Fixture(self.root,self.option)
        self.f.archive.write_bytes(self.raw)
        self.f.snapshot['files']['data.000']=b.fp(self.f.archive.stat())
        self.f.snapshot['directory_identity']=b.fp(self.f.game.stat())
        self.f.meta(self.f.inv,'local_storage_snapshot',self.f.snapshot)
        self.f.update(self.f.inv,'UPDATE archives SET size=?',(len(self.raw),))
        self.f.update(self.f.inv,'CREATE TABLE refs(prefix BLOB,archive_id INTEGER,raw_offset INTEGER,span INTEGER)')
        self.addref()
    def tearDown(self):self.temp.cleanup()
    def addref(self,*,prefix=None,aid=0,offset=0,span=None):
        self.f.update(self.f.inv,'INSERT INTO refs VALUES (?,?,?,?)',(bytes.fromhex(self.ek)[:9] if prefix is None else prefix,aid,offset,len(self.raw) if span is None else span))
    def search(self,options=None,**kw):
        watch=b.Watch();db=sqlite3.connect(':memory:',uri=True)
        try:
            b.attach(db,watch,self.f.inv,'i');return r.search_refs(db,options or [self.option],self.f.snapshot,**kw)
        finally:db.close()
    def test_saved_refs_find_source_outside_candidates(self):
        self.f.update(self.f.inv,'DELETE FROM candidates')
        rows,report=self.search();self.assertEqual(len(rows),1);self.assertEqual(report['source_ekeys_with_prefix_candidates'],1)
    def test_no_matching_refs_unknown(self):
        self.f.update(self.f.inv,'DELETE FROM refs');rows,report=self.search()
        self.assertEqual(rows,[]);self.assertTrue(report['no_prefix_match_is_not_global_absence'])
    def test_duplicate_reference_dedup(self):
        self.addref();rows,report=self.search();self.assertEqual(len(rows),1);self.assertEqual(report['matched_reference_rows'],2)
    def test_missing_archive_is_not_opened(self):
        self.f.update(self.f.inv,'DELETE FROM refs');self.addref(aid=100)
        rows,report=self.search();self.assertEqual(rows,[]);self.assertEqual(report['invalid_or_unavailable_archive_reference_rows'],1)
    def test_bounds_rejected(self):
        self.f.update(self.f.inv,'DELETE FROM refs');self.addref(offset=1)
        rows,report=self.search();self.assertEqual(rows,[])
    def test_path_traversal_rejected(self):
        self.f.update(self.f.inv,'UPDATE archives SET name=?',('../other',));self.assertEqual(self.search()[0],[])
    def test_ambiguous_archive_rejected(self):
        self.f.update(self.f.inv,'UPDATE archives SET ambiguous=1');self.assertEqual(self.search()[0],[])
    def test_prefix_collision_retained_not_proven(self):
        wrong=self.ek[:18]+('0' if self.ek[18]!='0' else '1')+self.ek[19:]
        rows,_=self.search([mkoption(wrong,self.ds)]);self.assertEqual(len(rows),1)
        proof,private,usage=r.verify_one(rows,self.f.snapshot,b.Watch());self.assertIsNone(proof)
    def test_read_exact_source(self):
        rows,_=self.search();proof,private,usage=r.verify_one(rows,self.f.snapshot,b.Watch())
        self.assertEqual(proof['derived_source_ckey'],self.ck);self.assertEqual(usage['archive_payload_bytes_read'],len(self.raw))
        self.assertFalse(private['apply_authorized'])
    def test_30_byte_envelope(self):
        self.f.archive.write_bytes(b'x'*30+self.raw)
        self.f.snapshot['files']['data.000']=b.fp(self.f.archive.stat())
        self.f.update(self.f.inv,'UPDATE archives SET size=?',(len(self.raw)+30,))
        self.f.update(self.f.inv,'UPDATE refs SET span=?',(len(self.raw)+30,))
        rows,_=self.search();proof,private,usage=r.verify_one(rows,self.f.snapshot,b.Watch())
        self.assertIsNotNone(proof);self.assertEqual(private['source_offset'],30)
    def test_metadata_only_no_archive_open(self):
        rows,_=self.search()
        with patch.object(Path,'open',side_effect=AssertionError('payload not allowed')):
            proof,_,usage=r.verify_one(rows,self.f.snapshot,b.Watch(),budget=0)
        self.assertIsNone(proof);self.assertEqual(usage['archive_payload_bytes_read'],0)
    def test_reference_limit(self):
        self.addref()
        with patch.object(r,'MAX_MATCHES',1),self.assertRaisesRegex(b.BindingError,'matched_reference_limit'):self.search()
    def test_cancelled_query(self):
        with self.assertRaises((b.BindingError,sqlite3.OperationalError)):self.search(cancel=lambda:True,time_limit=-1)
    def test_changed_archive_rejected(self):
        rows,_=self.search();self.f.archive.write_bytes(self.raw+b'x')
        with self.assertRaisesRegex(b.BindingError,'fingerprint'):r.verify_one(rows,self.f.snapshot,b.Watch())
    def test_attempt_cap(self):
        rows,_=self.search();proof,_,usage=r.verify_one(rows,self.f.snapshot,b.Watch(),max_attempts=0)
        self.assertIsNone(proof);self.assertEqual(usage['archive_payload_bytes_read'],0)
    def test_byte_budget(self):
        rows,_=self.search();proof,_,usage=r.verify_one(rows,self.f.snapshot,b.Watch(),budget=len(self.raw)-1)
        self.assertIsNone(proof);self.assertEqual(usage['archive_payload_bytes_read'],0)
    def test_run_with_real_contract_and_no_network_no_source_writes(self):
        files=[p for p in self.f.lab.rglob('*') if p.is_file()]+[self.f.archive]
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        with patch.object(b,'load_metadata',return_value=([self.option],{'blocks':1},BINDING)),patch.object(socket,'socket',side_effect=AssertionError('network')):
            out,report=r.run(self.f.lab,output=self.root/'Results')
        self.assertEqual(report['status'],'one_source_encoded_identity_verified')
        self.assertEqual(before,{p:hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
        text=(out/'Retail-Refs-Source-to-share.json').read_text()
        self.assertNotIn(str(self.root),text);self.assertNotIn('source_path',text)
        self.assertFalse(report['patch_applied']);self.assertFalse(report['installation_ready'])
    def test_output_in_lab_rejected(self):
        with patch.object(b,'load_metadata',return_value=([self.option],{'blocks':1},BINDING)),self.assertRaisesRegex(b.BindingError,'outside_sources'):
            r.run(self.f.lab,output=self.f.lab/'BadResults')
    def test_read_cancelled(self):
        rows,_=self.search()
        with self.assertRaisesRegex(b.BindingError,'cancelled'):r.verify_one(rows,self.f.snapshot,b.Watch(),cancel=lambda:True)

if __name__=='__main__':unittest.main()
