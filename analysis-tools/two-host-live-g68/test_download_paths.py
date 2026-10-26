import unittest, json, hashlib, base64
from pathlib import Path
from download_path_audit import classify, load_reference
from semantic_audit import Audit

class T(unittest.TestCase):
    def setUp(self):
        self.path='/tpr/agent/data/ab/cd/abcdef0123456789abcdef0123456789'
        self.refs={self.path:[{'kind':'public_download_manifest_entry',
                              'product':'agent','public_encoded_bytes':100}]}

    def test_whole_path_only(self):
        self.assertTrue(classify(self.path,'GET',{},b'',self.refs)['whole_path_exactly_in_independent_public_reference'])
        for p in [self.path+'?id=SECRET',self.path+'/SECRET',self.path+'/',self.path.replace('/ab/','/ef/'),
                  self.path.replace('/data/','/%64ata/')]:
            out=classify(p,'GET',{},b'',self.refs)
            self.assertFalse(out['whole_path_exactly_in_independent_public_reference'])
            self.assertNotIn('SECRET',json.dumps(out))

    def test_body_does_not_become_clearance(self):
        out=classify(self.path,'POST',{},b'SECRET',self.refs)
        self.assertEqual(out['verdict'],'unknown_requires_more_evidence')
        self.assertNotIn('SECRET',json.dumps(out))

    def test_ranges_bounds_only_not_privacy_clearance(self):
        out=classify(self.path,'GET',{'range':['bytes=10-99']},b'',self.refs)
        self.assertTrue(out['range_inside_public_object_size_if_checkable'])
        self.assertFalse(out['range_matches_public_archive_record'])
        self.assertFalse(out['fingerprinting_absence_proven'])
        self.assertFalse(classify(self.path,'GET',{'range':['bytes=0-100']},b'',self.refs)['range_inside_public_object_size_if_checkable'])

    def test_unknown_archive_size_is_unknown(self):
        refs={self.path:[{'kind':'public_archive_key','product':'agent'}]}
        self.assertIsNone(classify(self.path,'GET',{'range':['bytes=0-99']},b'',refs)['range_inside_public_object_size_if_checkable'])

    def test_integration_without_exporting_observed_path(self):
        a=Audit(public_paths=self.refs)
        a.feed('x',('GET '+self.path+' HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n').encode())
        out=a.report()
        self.assertTrue(out['rows'][0]['public_download_path']['whole_path_exactly_in_independent_public_reference'])
        self.assertNotIn(self.path,json.dumps(out))

    def test_real_snapshot_pins_and_byte_lineage(self):
        base=Path(__file__).parent
        refs,summary=load_reference(base)
        self.assertTrue(summary['independent_of_installer_input'])
        self.assertFalse(summary['runtime_permission'])
        catalog=json.loads((base/'public-download-reference.json').read_text())
        fixtures=json.loads((base/'public-reference-fixtures.json').read_text())
        labels=set()
        for receipt in catalog['receipts']:
            blob=base64.b64decode(fixtures[receipt['label']],validate=True)
            self.assertEqual(hashlib.sha256(blob).hexdigest(),receipt['sha256'])
            self.assertEqual(len(blob),receipt['bytes'])
            labels.add(receipt['label'])
        for path,rows in refs.items():
            self.assertNotIn('?',path)
            for row in rows:
                self.assertIn(row['source_label'],labels)
                if row['kind'] in ('public_build_config','public_cdn_config','public_product_config'):
                    blob=base64.b64decode(fixtures[row['source_label']])
                    self.assertEqual(hashlib.md5(blob).hexdigest(),path.rsplit('/',1)[1])

    def test_DL_paths_reconstructed_from_verified_metadata_bytes(self):
        from public_codecs import decode_blte, parse_download
        base=Path(__file__).parent
        catalog=json.loads((base/'public-download-reference.json').read_text())
        fixtures={k:base64.b64decode(v) for k,v in
                  json.loads((base/'public-reference-fixtures.json').read_text()).items()}
        for product in ('agent','bna'):
            build={}
            for line in fixtures[product+'-build'].decode().splitlines():
                if line and not line.startswith('#'):
                    k,v=line.split(' = ',1);build[k]=v
            lines=[x for x in fixtures[product+'-cdns'].decode().splitlines()
                   if x and not x.startswith('#')]
            names=[x.split('!')[0] for x in lines[0].split('|')]
            cdn=next(dict(zip(names,line.split('|'))) for line in lines[1:]
                     if line.split('|')[0]=='us')
            ck,ek=build['download'].split()
            decoded_size,encoded_size=map(int,build['download-size'].split())
            blob=fixtures[product+'-download-manifest']
            self.assertEqual(len(blob),encoded_size)
            decoded=decode_blte(blob,decoded_size,ek)
            self.assertEqual(hashlib.md5(decoded).hexdigest(),ck)
            dl=parse_download(decoded)
            expected={}
            for row in dl['entries']:
                k=row['ekey']
                path='/'+cdn['Path']+'/data/'+k[:2]+'/'+k[2:4]+'/'+k
                expected[path]=row['encoded_bytes']
            actual={}
            for path,rows in catalog['paths'].items():
                for row in rows:
                    if row['product']==product and row['kind']=='public_download_manifest_entry':
                        actual[path]=row['public_encoded_bytes']
            self.assertEqual(actual,expected)