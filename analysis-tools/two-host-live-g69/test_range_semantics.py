import unittest,json,base64,hashlib
from pathlib import Path
from download_path_audit import Reference,range_semantics,key_origin,load_reference,classify

class T(unittest.TestCase):
    def setUp(self):
        self.path='/tpr/agent/data/ab/cd/abcdef0123456789abcdef0123456789'
        self.r=Reference()
        self.r.ranges={self.path:{'ranges':[
            {'start':10,'end':19,'basis':'complete_verified_archive_record'},
            {'start':20,'end':39,'basis':'complete_verified_archive_record'},
            {'start':50,'end':59,'basis':'complete_verified_archive_record'}]}}
        self.r.origins={'abcdef0123456789abcdef0123456789':['public_encoding_CKey']}
        self.r.prefixes={'/tpr/agent/data'}

    def test_exact_record_and_contiguous_union(self):
        for s in ('bytes=10-19','bytes=10-39'):
            out=range_semantics(self.path,[s],self.r)
            self.assertTrue(out['exact_public_boundary_match'])
            self.assertFalse(out['fingerprinting_absence_proven'])
            self.assertNotIn(s,json.dumps(out))

    def test_partial_or_gap_not_whole_public_records(self):
        for s in ('bytes=11-19','bytes=10-59','bytes=20-38'):
            self.assertFalse(range_semantics(self.path,[s],self.r)['exact_public_boundary_match'])
        self.assertTrue(range_semantics(self.path,['bytes=11-19'],self.r)['within_single_public_archive_record'])

    def test_bad_range_and_multi_value(self):
        for ranges in (['bytes=19-10'],['bytes=0-'],['bytes=0-7,10-19'],['bytes=10-19','bytes=20-39']):
            self.assertFalse(range_semantics(self.path,ranges,self.r)['exact_public_boundary_match'])

    def test_origin_does_not_become_endpoint_confirmation(self):
        out=key_origin(self.path,self.r)
        self.assertTrue(out['canonical_fanout_matches_key'])
        self.assertEqual(out['key_public_origins'],['public_encoding_CKey'])
        self.assertFalse(out['semantic_endpoint_confirmed'])
        self.assertNotIn('abcdef0123456789abcdef0123456789',json.dumps(out))

    def test_actual_verified_archive_ranges(self):
        from reference_index_parser import parse_index,Rejected
        base=Path(__file__).parent
        cat=json.loads((base/'public-download-reference.json').read_text())
        fixtures={k:base64.b64decode(v) for k,v in
                  json.loads((base/'public-reference-fixtures.json').read_text()).items()}
        refs,_=load_reference(base)
        checked=0
        for path,ref in cat['range_references'].items():
            if not ref['source_label'].startswith('agent-archive-index-'):
                continue
            blob=fixtures[ref['source_label']]
            key=path.rsplit('/',1)[1]
            parsed=parse_index(blob,key,'archive_index')
            actual={(x['start'],x['end']) for x in ref['ranges']}
            expected={(x['offset'],x['offset']+x['encoded_bytes']-1) for x in parsed['entries']}
            self.assertEqual(actual,expected)
            for lo,hi in expected:
                self.assertTrue(range_semantics(path,['bytes='+str(lo)+'-'+str(hi)],refs)['exact_public_boundary_match'])
            corrupt=bytearray(blob);corrupt[0]^=1
            with self.assertRaises(Rejected):
                parse_index(bytes(corrupt),key,'archive_index')
            checked+=1
        self.assertEqual(checked,3)

    def test_actual_BLTE_boundaries(self):
        base=Path(__file__).parent
        cat=json.loads((base/'public-download-reference.json').read_text())
        fixtures={k:base64.b64decode(v) for k,v in
                  json.loads((base/'public-reference-fixtures.json').read_text()).items()}
        for path,ref in cat['range_references'].items():
            if ref['source_label'].startswith('agent-archive-index-'):
                continue
            b=fixtures[ref['source_label']]
            self.assertEqual(ref['public_size'],len(b))
            self.assertEqual(b[:4],b'BLTE')
            hs=int.from_bytes(b[4:8],'big')
            for r in ref['ranges']:
                self.assertTrue(0<=r['start']<=r['end']<len(b))
                if r['basis']=='BLTE_complete_header_and_chunk_table':
                    self.assertEqual((r['start'],r['end']),(0,hs-1))