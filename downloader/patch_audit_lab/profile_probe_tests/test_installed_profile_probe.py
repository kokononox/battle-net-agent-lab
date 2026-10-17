"""Synthetic game roots; only optional pinned config bytes are real metadata."""
import contextlib,hashlib,io,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import installed_profile_probe as p
import installed_profile_launcher as launch
SECRET='PRIVATE_ACCOUNT_AND_KEYRING_VALUE'
CONFIG=b'build-uid = wow\nbuild-name = WOW-70391patch12.1.5_Retail\nUnknown_Field = PRIVATE_ACCOUNT_AND_KEYRING_VALUE\n'
TAGS='Windows x86_64 EU code : enUS? speech text : acct-PRIVATE123? geoip-PRIVATE456?'

def info(key=None,tags=TAGS,version='12.1.5.70391',active='1',product='wow'):
 key=key or hashlib.md5(CONFIG).hexdigest()
 return ('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Tags!STRING:0|Product!STRING:0|KeyRing!STRING:0\n'+active+'|'+key+'|'+version+'|'+tags+'|'+product+'|'+SECRET+'\n').encode()

def game(root,config=CONFIG,raw=None):
 root.mkdir();key=hashlib.md5(config).hexdigest();path=root/'Data/config'/key[:2]/key[2:4]/key;path.parent.mkdir(parents=True);path.write_bytes(config);(root/'.build.info').write_bytes(info(key) if raw is None else raw);return root,path

def contents(root):return {str(x.relative_to(root)):(x.read_bytes(),p.fingerprint(x.stat())) for x in root.rglob('*') if x.is_file()}

class Parsing(unittest.TestCase):
 def test_whitelisted_active_row_drops_keyring(self):self.assertNotIn(SECRET,json.dumps(p.select_row(info())))
 def test_duplicate_header_rejected(self):
  with self.assertRaises(p.ProbeError):p.select_row(b'Active|Build Key|BuildKey\n1|a|b\n')
 def test_ambiguous_active_row_rejected(self):
  raw=info();raw+=raw.splitlines()[1]+b'\n'
  with self.assertRaises(p.ProbeError):p.select_row(raw)
 def test_inactive_row_not_selected(self):
  with self.assertRaises(p.ProbeError):p.select_row(info(active='0'))
 def test_classic_product_not_selected(self):
  with self.assertRaises(p.ProbeError):p.select_row(info(product='wow_classic'))
 def test_traversal_build_key_rejected(self):
  with self.assertRaises(p.ProbeError):p.select_row(info(key='../'+SECRET))
 def test_uppercase_key_rejected(self):
  with self.assertRaises(p.ProbeError):p.select_row(info(key='A'*32))
 def test_bad_row_width_rejected(self):
  with self.assertRaises(p.ProbeError):p.select_row(info()+b'bad|row\n')
 def test_bad_encoding_rejected(self):
  with self.assertRaises(p.ProbeError):p.select_row(b'\xff')
 def test_typed_header_and_BOM_supported(self):self.assertEqual(p.select_row(b'\xef\xbb\xbf'+info())['version'],'12.1.5.70391')
 def test_config_identity_md5_required(self):
  with self.assertRaises(p.ProbeError):p.verify_config(CONFIG,'0'*32,'')
 def test_version_mismatch_rejected(self):
  with self.assertRaises(p.ProbeError):p.verify_config(CONFIG,hashlib.md5(CONFIG).hexdigest(),'1.2.3.4')
 def test_duplicate_config_identity_rejected(self):
  raw=CONFIG+b'build-uid = wow\n'
  with self.assertRaises(p.ProbeError):p.verify_config(raw,hashlib.md5(raw).hexdigest(),'')
 def test_nonretail_config_rejected(self):
  raw=CONFIG.replace(b'_Retail',b'_Classic')
  with self.assertRaises(p.ProbeError):p.verify_config(raw,hashlib.md5(raw).hexdigest(),'')
 def test_missing_version_derived_from_verified_config(self):self.assertEqual(p.verify_config(CONFIG,hashlib.md5(CONFIG).hexdigest(),''),'12.1.5.70391')
 def test_supported_profile_projection(self):
  profile,counts,error=p.profile_details(TAGS);self.assertEqual(profile,{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']});self.assertIsNone(error);self.assertEqual(counts['account_qualifier_count'],1);self.assertNotIn('PRIVATE',json.dumps((profile,counts,error)))
 def test_multiple_locales_preserved(self):self.assertEqual(p.profile_details('Windows x86_64 EU enUS frFR')[0]['locales'],['enUS','frFR'])
 def test_geoip_qualifier_never_supplies_region(self):self.assertIsNone(p.profile_details('Windows x86_64 enUS geoip-EU?')[0])
 def test_missing_locale_no_guess(self):self.assertIsNone(p.profile_details('Windows x86_64 EU')[0])
 def test_ambiguous_region_no_guess(self):self.assertIsNone(p.profile_details('Windows x86_64 EU US enUS')[0])
 def test_unknown_tag_fails_closed_without_leak(self):
  result=p.profile_details('Windows x86_64 EU enUS '+SECRET+'?');self.assertIsNone(result[0]);self.assertEqual(result[2],'unknown_installed_tag_no_guess');self.assertNotIn(SECRET,json.dumps(result))
 def test_unsupported_locale_no_fallback(self):self.assertEqual(p.profile_details('Windows x86_64 EU enGB')[2],'unsupported_installed_profile_no_fallback')
 def test_optional_known_tokens_not_proven_vendor_policy(self):self.assertIsNotNone(p.profile_details('Windows? x86_64? EU? enUS?')[0])
 def test_empty_and_malformed_tags_unknown(self):
  for tags in ('',':','Windows::enUS','Windows x86_64 EU enUS??'):
   with self.subTest(tags=tags):self.assertIsNone(p.profile_details(tags)[0])

class Integration(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.game,self.config=game(self.root/'game')
 def tearDown(self):self.temp.cleanup()
 def test_exactly_two_game_content_reads_and_no_enumeration_or_network(self):
  opened=[];original=Path.open
  def track(path,*args,**kw):
   if self.game in path.parents:opened.append(path)
   return original(path,*args,**kw)
  import urllib.request
  with patch.object(Path,'open',track),patch.object(os,'listdir',side_effect=AssertionError('no scan')),patch.object(Path,'rglob',side_effect=AssertionError('no scan')),patch.object(urllib.request,'urlopen',side_effect=AssertionError('no network')):q,_=p.read(self.game)
  self.assertEqual(opened,[self.game/'.build.info',self.config]);self.assertEqual(q['scope']['game_metadata_files_read'],2);self.assertEqual(q['scope']['archive_payload_bytes_read'],0)
 def test_game_metadata_unchanged(self):
  before=contents(self.game);q,_=p.read(self.game);self.assertEqual(before,contents(self.game));self.assertFalse(q['game_files_modified']);self.assertFalse(q['installation_ready'])
 def test_no_paths_labels_keyring_or_unknown_config_export(self):
  q,_=p.read(self.game);text=json.dumps(q);self.assertNotIn(str(self.game),text);self.assertNotIn(SECRET,text);self.assertNotIn('PRIVATE123',text);self.assertNotIn('PRIVATE456',text);self.assertNotIn('Unknown_Field',text)
 def test_unknown_profile_yields_safe_diagnostic_not_guessed_profile(self):
  (self.game/'.build.info').write_bytes(info(tags='Windows x86_64 EU enUS '+SECRET+'?'));q,_=p.read(self.game);self.assertEqual(q['status'],'identity_verified_profile_unresolved');self.assertIsNone(q['profile']);self.assertNotIn(SECRET,json.dumps(q))
 def test_missing_config_does_not_fall_back_or_scan(self):
  self.config.unlink()
  with patch.object(os,'listdir',side_effect=AssertionError('no scan')):
   with self.assertRaises(OSError):p.read(self.game)
 def test_build_info_cap_before_open(self):
  (self.game/'.build.info').write_bytes(b'x'*(p.MAX_INFO+1))
  with patch.object(Path,'open',side_effect=AssertionError('must reject before opening')):
   with self.assertRaises(p.ProbeError):p.read(self.game)
 def test_config_cap(self):
  self.config.write_bytes(b'x'*(p.MAX_CONFIG+1))
  with self.assertRaises(p.ProbeError):p.read(self.game)
 def test_input_symlink_rejected(self):
  orig=self.root/'real-info';(self.game/'.build.info').rename(orig);(self.game/'.build.info').symlink_to(orig)
  with self.assertRaises(p.ProbeError):p.read(self.game)
 def test_input_hardlink_rejected(self):
  os.link(self.game/'.build.info',self.root/'shared')
  with self.assertRaises(p.ProbeError):p.read(self.game)
 def test_prepublication_change_rejected(self):
  q,private=p.read(self.game);self.config.write_bytes(CONFIG+b'changed')
  with self.assertRaises(p.ProbeError):p.publish(q,private,self.root/'out')
  self.assertFalse((self.root/'out').exists())
 def test_publish_external_report_only(self):
  before=contents(self.game);q,private=p.read(self.game);final=p.publish(q,private,self.root/'out');self.assertEqual(json.loads(final.read_text()),q);self.assertEqual(list(final.parent.iterdir()),[final]);self.assertEqual(contents(self.game),before)
 def test_publication_inside_game_forbidden(self):
  q,private=p.read(self.game)
  with self.assertRaises(p.ProbeError):p.publish(q,private,self.game/'Results')
 def test_publication_inside_Lab_forbidden(self):
  lab=self.root/'lab';lab.mkdir();(lab/'LAB-ONLY.json').write_text('{}');q,private=p.read(self.game)
  with self.assertRaises(p.ProbeError):p.publish(q,private,lab/'Results')
 def test_existing_output_forbidden(self):
  out=self.root/'out';out.mkdir();(out/'KEEP').write_bytes(b'KEEP');q,private=p.read(self.game)
  with self.assertRaises(p.ProbeError):p.publish(q,private,out)
  self.assertEqual((out/'KEEP').read_bytes(),b'KEEP')
 def test_racing_final_not_overwritten(self):
  q,private=p.read(self.game);link=os.link
  def race(src,dst):Path(dst).write_bytes(b'KEEP');link(src,dst)
  with patch.object(p.sys,'platform','linux'),patch.object(p.os,'link',side_effect=race):
   with self.assertRaises(FileExistsError):p.publish(q,private,self.root/'out')
  self.assertEqual((self.root/'out/INSTALLED-PROFILE-to-share.json').read_bytes(),b'KEEP');self.assertFalse(list((self.root/'out').glob('*.pending')))
 def test_postpublication_change_removes_own_final(self):
  q,private=p.read(self.game);link=os.link
  def change(src,dst):link(src,dst);self.config.write_bytes(CONFIG+b'changed')
  with patch.object(p.sys,'platform','linux'),patch.object(p.os,'link',side_effect=change):
   with self.assertRaises(p.ProbeError):p.publish(q,private,self.root/'out')
  self.assertFalse(list((self.root/'out').iterdir()))
 def test_windows_dispatch_rename_without_link_or_replace(self):
  with patch.object(p.sys,'platform','win32'),patch.object(p.os,'rename') as rename,patch.object(p.os,'link',side_effect=AssertionError('no hardlink')),patch.object(p.os,'replace',side_effect=AssertionError('no overwrite')):p.publish_noreplace('a','b');rename.assert_called_once_with('a','b')
 def test_windows_publication_modeled_success_without_production_hardlink(self):
  q,private=p.read(self.game);link=os.link
  def modeled_rename(src,dst):link(src,dst);Path(src).unlink()
  with patch.object(p.sys,'platform','win32'),patch.object(p.os,'rename',side_effect=modeled_rename),patch.object(p.os,'link',side_effect=AssertionError('no production hardlink')):
   final=p.publish(q,private,self.root/'out')
  self.assertEqual(json.loads(final.read_text()),q);self.assertEqual(list(final.parent.iterdir()),[final])
 def test_windows_failure_cleans_pending_without_unsafe_fallback(self):
  q,private=p.read(self.game);ex=OSError(22,SECRET);ex.winerror=1
  with patch.object(p.sys,'platform','win32'),patch.object(p.os,'rename',side_effect=ex),patch.object(p.os,'link',side_effect=AssertionError('no fallback')):
   with self.assertRaises(OSError):p.publish(q,private,self.root/'out')
  self.assertFalse(list((self.root/'out').iterdir()))
 def test_safe_error_omits_message_and_paths(self):
  ex=OSError(22,SECRET,SECRET);ex.winerror=1;q=p.public_error(ex,'read_named_build_config');self.assertNotIn(SECRET,json.dumps(q));self.assertEqual(q['winerror'],1)
 def test_cancel_before_reads(self):
  with patch.object(Path,'open',side_effect=AssertionError('no reads')):
   with self.assertRaises(p.ProbeError):p.read(self.game,cancel=lambda:True)
 def test_launcher_cancel_does_not_read(self):
  tk=types.ModuleType('tkinter');tk.Tk=lambda:types.SimpleNamespace(withdraw=lambda:None,destroy=lambda:None);tk.filedialog=types.SimpleNamespace(askdirectory=lambda **kw:'')
  with patch.dict(sys.modules,{'tkinter':tk,'tkinter.filedialog':tk.filedialog}),patch.object(p,'read',side_effect=AssertionError('no reads')),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(launch.main(),0)
 def test_pinned_real_config_in_synthetic_root(self):
  raw=Path(os.environ['PROBE_REAL_CONFIG']).read_bytes();other=self.root/'pinned';g,_=game(other,config=raw,raw=info(key=hashlib.md5(raw).hexdigest()));q,_=p.read(g);self.assertTrue(q['research_target_comparison']['same_build_config']);self.assertFalse(q['actual_required_install_set_known'])
if __name__=='__main__':unittest.main()
