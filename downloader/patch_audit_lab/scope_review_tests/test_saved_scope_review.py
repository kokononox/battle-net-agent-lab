"""Synthetic saved Lab/game/Download metadata; real pinned audit metadata only.
Never claims a real user's Lab or native Windows was executed here.
"""
import hashlib,io,json,os,sqlite3,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import saved_scope_review as s
import source_binding as b
from profile_probe_tests.test_installed_profile_probe import game,CONFIG,contents as game_contents
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'local_review_tests'))
from fixtures import Fixture,contents

PROFILE={'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']}
def manifest(n=8,version=3,flags=0,checksum=0,tags=None,extra=b'\0'*4):
    if tags is None:tags=[('Windows',1,0xf0),('OSX',1,0x0c),('x86_64',2,0xf0),('x86_32',2,0x0c),('enUS',3,0xc0),('frFR',3,0x30),('EU',4,0xc0),('US',4,0x30),('text',0,0xff)]
    out=b'DL'+bytes([version,16,checksum])+n.to_bytes(4,'big')+len(tags).to_bytes(2,'big')
    if version>=2:out+=bytes([flags])
    if version>=3:out+=extra
    for i in range(n):out+=(i+1).to_bytes(16,'big')+(i+1).to_bytes(5,'big')+b'\x02'+bytes(4*checksum+flags)
    width=(n+7)//8
    for text,kind,mask in tags:out+=text.encode()+b'\0'+kind.to_bytes(2,'big')+mask.to_bytes(width,'big')
    return out

def parse(raw,profile=PROFILE,check=lambda:None):return s.parse_manifest(s.ManifestReader(io.BytesIO(raw),len(raw),check),profile)

class Parser(unittest.TestCase):
    def test_shared_and_unclassified_bits_kept(self):
        q=parse(manifest());self.assertEqual(q['diagnostic_selected_records'],4);self.assertEqual(q['diagnostic_unselected_records'],4)
    def test_counts_are_records_not_unique_objects(self):self.assertIn('NOT_unique',parse(manifest())['selection_unit'])
    def test_no_vendor_or_checksum_algorithm_proof(self):
        q=parse(manifest(checksum=1));self.assertTrue(q['record_checksums_present']);self.assertFalse(q['record_checksum_algorithm_validated']);self.assertFalse(q['vendor_install_policy_proven'])
    def test_versions_one_two_three(self):
        for v in (1,2,3):
            with self.subTest(v=v):self.assertEqual(parse(manifest(version=v))['format_version'],v)
    def test_optional_high_bit_explicit_normalization(self):
        tags=[('Windows',0x4001,255),('x86_64',2,255),('enUS',3,255),('EU',4,255)];q=parse(manifest(tags=tags));self.assertEqual(q['tags_with_optional_kind_bit'],1);self.assertEqual(q['diagnostic_selected_records'],8)
    def test_multilocale_or(self):
        q=parse(manifest(),dict(PROFILE,locales=['enUS','frFR']));self.assertEqual(q['diagnostic_selected_records'],4)
    def test_dimensions_and_not_or(self):
        tags=[('Windows',1,0xf0),('OSX',1,0x0f),('x86_64',2,0xaa),('x86_32',2,0x55),('enUS',3,255),('EU',4,255)];self.assertEqual(parse(manifest(tags=tags))['diagnostic_selected_records'],2)
    def test_bad_magic(self):
        with self.assertRaises(b.BindingError):parse(b'XX'+manifest()[2:])
    def test_unknown_version(self):
        raw=bytearray(manifest());raw[2]=4
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_full_ekey_required(self):
        raw=bytearray(manifest());raw[3]=9
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_nonzero_reserved(self):
        with self.assertRaises(b.BindingError):parse(manifest(extra=b'\0\0\0\x01'))
    def test_invalid_checksum_marker(self):
        raw=bytearray(manifest());raw[4]=2
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_flag_limit(self):
        with self.assertRaises(b.BindingError):parse(manifest(flags=5))
    def test_count_limit(self):
        raw=bytearray(manifest());raw[5:9]=(s.MAX_RECORDS+1).to_bytes(4,'big')
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_tag_limit(self):
        raw=bytearray(manifest());raw[9:11]=(s.MAX_TAGS+1).to_bytes(2,'big')
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_zero_key(self):
        raw=bytearray(manifest());raw[16:32]=bytes(16)
        with self.assertRaises(b.BindingError):parse(bytes(raw))
    def test_truncated(self):
        with self.assertRaises(b.BindingError):parse(manifest()[:-1])
    def test_trailing(self):
        with self.assertRaises(b.BindingError):parse(manifest()+b'x')
    def test_unknown_dimension_value(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('PRIVATE_UNKNOWN',1,255)]))
    def test_unknown_kind(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('PRIVATE_UNKNOWN',6,255)]))
    def test_wrong_kind_known_value(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('Windows',2,255)]))
    def test_duplicate_normalized_optional_tag(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('Windows',1,255),('Windows',0x4001,255)]))
    def test_requested_tag_missing_no_fallback(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[]))
    def test_long_name(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('X'*257,0,255)]))
    def test_controls_in_name(self):
        with self.assertRaises(b.BindingError):parse(manifest(tags=[('XX\n',0,255)]))
    def test_nonzero_padding_rejected(self):
        with self.assertRaises(b.BindingError):parse(manifest(n=7,tags=[('Windows',1,255)]))
    def test_padding_not_counted(self):
        tags=[('Windows',1,254),('x86_64',2,254),('enUS',3,254),('EU',4,254)];self.assertEqual(parse(manifest(n=7,tags=tags))['diagnostic_selected_records'],7)
    def test_cancel_called(self):
        def stop():raise b.BindingError('cancelled')
        with self.assertRaises(b.BindingError):parse(manifest(),check=stop)
    def test_single_pass_digest_covers_all_bytes(self):
        raw=manifest();r=s.ManifestReader(io.BytesIO(raw),len(raw),lambda:None);s.parse_manifest(r,PROFILE);self.assertEqual(r.used,len(raw));self.assertEqual(r.md5.hexdigest(),hashlib.md5(raw).hexdigest());self.assertEqual(r.sha.hexdigest(),hashlib.sha256(raw).hexdigest())

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit=Path(os.environ['SCOPE_PORTABLE']).resolve()/'pinned_metadata';cls.auditwatch=b.Watch();cls.real_metadata=b.load_metadata(cls.audit,cls.auditwatch)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.game,self.config=game(self.root/'game');self.f=Fixture(self.root,self.real_metadata[2],(Path(os.environ['SCOPE_SOURCE_ARCHIVE'])).read_bytes())
        # Move the fixture's saved storage under the selected game then rewrite
        # synthetic saved coordinates. Production validators are NOT weakened.
        data=self.game/'Data/data';self.f.storage.rename(data);self.f.storage=data;self.f.archive=data/'data.000'
        self.f.edit(self.f.ev,'UPDATE evidence SET source_path=?',(str(self.f.archive),));self.f.refresh_snapshot()
        self.raw=manifest();self.key=hashlib.md5(self.raw).hexdigest();self.path=self.f.objects/(self.key+'-'+str(len(self.raw))+'.decoded')
        self.config_data={'download':[self.key,self.real_metadata[2]['download_ekey']],'download-size':[str(len(self.raw)),'1']}
        self.target=dict(self.real_metadata[2],download_ckey=self.key)
        # All four DBs carry the same synthetic target CKey, no real manifest is
        # fabricated to match the pinned CKey. Real pinned parser used in bind.
        for path in (self.f.plan,self.f.queue,self.f.inv,self.f.ev):self.f.edit(path,'UPDATE metadata SET value=? WHERE name=?',(json.dumps(self.target),'target_binding'))
        self.bound_metadata=(self.real_metadata[0],self.real_metadata[1],dict(self.real_metadata[2],download_ckey=self.key))
    def tearDown(self):self.tmp.cleanup();self.auditwatch.check()
    def review(self,**kwargs):
        real_config=a_config=s.a.config
        def config(raw,key):
            q=real_config(raw,key);return dict(q,**self.config_data)
        with patch.object(b,'load_metadata',return_value=self.bound_metadata),patch.object(s.a,'config',side_effect=config):return s.review(self.f.lab,self.audit,self.game,**kwargs)
    def test_missing_exact_cache_is_unknown_not_corrupt(self):
        q,_=self.review();self.assertEqual(q['status'],'bound_download_metadata_unavailable');self.assertIsNone(q['diagnostic_projection']);self.assertFalse(q['installation_ready']);self.assertEqual(q['scope']['archive_payload_bytes_read'],0)
    def test_exact_saved_cache_validated_and_projected(self):
        self.path.write_bytes(self.raw);q,_=self.review();self.assertEqual(q['status'],'bound_download_diagnostic_projection_complete');self.assertTrue(q['download_metadata']['content_identity_revalidated']);self.assertEqual(q['diagnostic_projection']['diagnostic_selected_records'],4);self.assertEqual(q['scope']['saved_download_metadata_bytes_read'],len(self.raw))
    def test_no_game_archive_or_other_cache_opens_or_network(self):
        self.path.write_bytes(self.raw);original=Path.open;opened=[]
        def track(path,*args,**kw):
            if path==self.f.archive:raise AssertionError('archive payload forbidden')
            if self.game in path.parents:opened.append(path)
            return original(path,*args,**kw)
        import urllib.request
        with patch.object(Path,'open',track),patch.object(urllib.request,'urlopen',side_effect=AssertionError('network forbidden')),patch.object(s.a.Fetcher,'get',side_effect=AssertionError('fetch forbidden')):self.review()
        self.assertEqual(opened,[self.game/'.build.info',self.config])
    def test_game_and_lab_bytes_fingerprints_unchanged(self):
        self.path.write_bytes(self.raw);before=contents(self.root);self.review();self.assertEqual(before,contents(self.root))
    def test_arbitrary_inventory_is_not_accepted_as_manifest(self):
        (self.f.objects/'inventory-not-authoritative.sqlite').write_bytes(self.raw);q,_=self.review();self.assertEqual(q['status'],'bound_download_metadata_unavailable')
    def test_manifest_ckey_mismatch(self):
        self.path.write_bytes(self.raw[:-1]+bytes([self.raw[-1]^0x80]))
        with self.assertRaisesRegex(b.BindingError,'saved_download_ckey_mismatch'):self.review()
    def test_manifest_size_mismatch(self):
        self.path.write_bytes(self.raw+b'x')
        with self.assertRaisesRegex(b.BindingError,'saved_download_size_conflict'):self.review()
    def test_manifest_symlink(self):
        other=self.root/'other';other.write_bytes(self.raw);self.path.symlink_to(other)
        with self.assertRaises(b.BindingError):self.review()
    def test_manifest_hardlink(self):
        other=self.root/'other';other.write_bytes(self.raw);os.link(other,self.path)
        with self.assertRaises(b.BindingError):self.review()
    def test_other_game_same_identity_rejected(self):
        other,_=game(self.root/'other');(other/'Data/data').mkdir();old=self.game;self.game=other
        try:
            with self.assertRaisesRegex(b.BindingError,'selected_game_not_saved_snapshot_storage'):self.review()
        finally:self.game=old
    def test_changed_saved_archive_stat_rejected_without_content_read(self):
        self.f.archive.write_bytes(b'CHANGED')
        with self.assertRaises(b.BindingError):self.review()
    def test_added_saved_storage_entry_rejected(self):
        (self.f.storage/'extra').write_bytes(b'x')
        with self.assertRaises(b.BindingError):self.review()
    def test_unresolved_profile_rejected(self):
        raw=(self.game/'.build.info').read_bytes();(self.game/'.build.info').write_bytes(raw.replace(b'enUS?',b'UNRECOGNIZED_PRIVATE?'))
        with self.assertRaisesRegex(b.BindingError,'installed_profile_unresolved_no_guess'):self.review()
    def test_cancelled_no_output(self):
        with self.assertRaises(b.BindingError):self.review(cancel=lambda:True)
    def test_safe_public_report_no_paths_private_labels(self):
        self.path.write_bytes(self.raw);q,_=self.review();text=json.dumps(q);self.assertNotIn(str(self.root),text);self.assertNotIn('PRIVATE',text);self.assertNotIn('acct-',text);self.assertNotIn('geoip-',text)
    def test_error_output_no_path_leak(self):
        q=s.public_error(OSError(22,'PRIVATE_PATH_HERE'),'locate_saved_download');self.assertEqual(q['errno'],22);self.assertNotIn('PRIVATE',json.dumps(q))
    def test_publish_separate_output(self):
        self.path.write_bytes(self.raw);q,private=self.review();before=contents(self.f.lab);final=s.publish(q,private,self.root/'reports/new');self.assertEqual(json.loads(final.read_text()),q);self.assertEqual(before,contents(self.f.lab))
    def test_publish_after_input_change_rejected(self):
        q,private=self.review();self.config.write_bytes(CONFIG+b'changed')
        with self.assertRaises(b.BindingError):s.publish(q,private,self.root/'new')
    def test_publish_missing_manifest_appeared_rejected(self):
        q,private=self.review();self.path.write_bytes(self.raw)
        with self.assertRaisesRegex(b.BindingError,'download_metadata_appeared_retry_required'):s.publish(q,private,self.root/'new')
    def test_publish_under_game_lab_audit_or_parent_rejected(self):
        q,private=self.review()
        for output in (self.game/'new',self.f.lab/'new',self.audit/'new',self.root):
            with self.subTest(output=str(output)):
                with self.assertRaises(b.BindingError):s.publish(q,private,output)
    def test_publish_existing_output_rejected(self):
        q,private=self.review();out=self.root/'new';out.mkdir()
        with self.assertRaises(b.BindingError):s.publish(q,private,out)
    def test_publish_racing_final_preserved(self):
        q,private=self.review();out=self.root/'new'
        def race(temp,final):final.write_text('OTHER');raise FileExistsError()
        with patch.object(s.p,'publish_noreplace',side_effect=race):
            with self.assertRaises(FileExistsError):s.publish(q,private,out)
        self.assertEqual((out/'SCOPE-REVIEW-to-share.json').read_text(),'OTHER');self.assertFalse(list(out.glob('*.pending')))
    def test_postpublication_change_own_report_removed(self):
        q,private=self.review();out=self.root/'new'
        def progress(stage):
            if stage=='postpublication_recheck':self.config.write_bytes(CONFIG+b'changed')
        with self.assertRaises(b.BindingError):s.publish(q,private,out,progress=progress)
        self.assertFalse((out/'SCOPE-REVIEW-to-share.json').exists());self.assertFalse(list(out.glob('*.pending')))
    def test_windows_no_replace_contract_no_hardlink(self):
        q,private=self.review();out=self.root/'new';real_rename=os.rename
        def winrename(src,dst):
            if Path(dst).exists():raise FileExistsError()
            return real_rename(src,dst)
        with patch.object(s.p.sys,'platform','win32'),patch.object(os,'rename',side_effect=winrename),patch.object(os,'link',side_effect=AssertionError('hardlink unsupported')):final=s.publish(q,private,out)
        self.assertEqual(json.loads(final.read_text()),q)

if __name__=='__main__':unittest.main()
