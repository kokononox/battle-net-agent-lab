"""Offline snapshot reconciliation and adversarial parser checks."""
import ast,base64,copy,hashlib,json,socket,struct,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import analyze as a
from encoding import parse_encoding,Rejected
from codec import parse_install,parse_download
class OfflineTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with patch('socket.socket',side_effect=AssertionError('network_forbidden')):
   cls.data,cls.objects,cls.build,cls.product=a.inputs();cls.b=cls.data['encoding'];cls.e=parse_encoding(cls.b);cls.i=parse_install(cls.data['install']);cls.d=parse_download(cls.data['download'])
 def setUp(self):self.guard=patch('socket.socket',side_effect=AssertionError('network_forbidden'));self.guard.start()
 def tearDown(self):self.guard.stop()
 def layout(self,b=None):
  b=b or self.b;h=struct.unpack('>2sBBBHHIIBI',b[:22]);ct=22+h[9];cd=ct+32*h[6];et=cd+1024*h[4]*h[6];ed=et+32*h[7]
  return h,ct,cd,et,ed
 def mutate_page(self,kind,page,rel,new):
  b=bytearray(self.b);h,ct,cd,et,ed=self.layout();size=1024*(h[4] if kind=='c' else h[5]);table=ct if kind=='c' else et;start=(cd if kind=='c' else ed)+page*size
  b[start+rel:start+rel+len(new)]=new;b[table+32*page+16:table+32*page+32]=hashlib.md5(b[start:start+size]).digest();return bytes(b)
 def reconcile(self,e=None,i=None,d=None):return a.reconcile(e or self.e,i or self.i,d or self.d,self.build,self.product)
 def test_pinned_source_bytes(self):
  data,_,_,_=a.inputs();self.assertEqual(data,self.data)
 def test_all_pages_checked(self):
  self.assertEqual(len(self.e['pages']),15);self.assertTrue(all(p['verified'] for p in self.e['pages']));self.assertEqual(len(self.e['ckey_mappings']),958);self.assertEqual(len(self.e['ekey_specs']),958)
 def test_all_install_paths_reconcile(self):
  s,rows,_=self.reconcile();self.assertEqual(s['reconciliation_status'],'metadata_consistent');self.assertEqual(s['install_paths_mapping_verified'],1157);self.assertEqual(s['independent_join_validated_rows'],1157);self.assertFalse(s['mapping_issues']);self.assertFalse(s['download_metadata_issues'])
 def test_literal_windows_candidates(self):
  s,rows,c=self.reconcile();self.assertEqual(s['windows_literal_tag_install_paths'],360);self.assertEqual(len(c),196);self.assertEqual(s['independent_windows_unique_objects'],196);self.assertEqual(s['independent_windows_paths'],360);self.assertTrue(all(r['approval_state']=='pending_payload_and_tag_review' and r['payload_sha256'] is None for r in c))
 def test_bit_order_known_platform_examples(self):
  mem=a.membership(self.i);self.assertEqual(self.i['entries'][0]['name'],'Battle.net Launcher.exe');self.assertIn('Windows',mem[0]);self.assertNotIn('OSX',mem[0]);self.assertIn('OSX',mem[1]);self.assertNotIn('Windows',mem[1]);dl=a.membership(self.d);self.assertIn('Windows',dl[0]);self.assertIn('OSX',dl[0])
 def test_preserves_install_aliases(self):
  s,rows,c=self.reconcile();self.assertEqual(len(rows),1157);self.assertEqual(len({r['ckey'] for r in rows}),953);self.assertTrue(any(len(x['install_indices'])>1 for x in c))
 def test_extra_download_is_root_not_ignored(self):
  s,_,_=self.reconcile();self.assertTrue(s['download_extra_explained_as_root']);self.assertEqual(len(s['download_extra_objects']),1);self.assertIn(s['download_extra_objects'][0]['ekey'],s['root_ekeys'])
 def test_every_page_corruption_rejected(self):
  h,ct,cd,et,ed=self.layout()
  for start,n,sz in ((cd,h[6],h[4]*1024),(ed,h[7],h[5]*1024)):
   for page in range(n):
    b=bytearray(self.b);b[start+page*sz+10]^=1
    with self.assertRaises(Rejected):parse_encoding(bytes(b))
 def test_page_index_first_key_rejected(self):
  b=bytearray(self.b);h,ct,cd,et,ed=self.layout();b[ct+5]^=1
  with self.assertRaises(Rejected):parse_encoding(bytes(b))
 def test_invalid_ckey_count_rejected_after_rehash(self):
  with self.assertRaises(Rejected):parse_encoding(self.mutate_page('c',0,0,b'\x11'))
 def test_missing_ekey_reference_rejected_after_rehash(self):
  with self.assertRaisesRegex(Rejected,'missing_ekey'):parse_encoding(self.mutate_page('c',0,22,b'\xff'*16))
 def test_espec_index_bounds_after_rehash(self):
  with self.assertRaisesRegex(Rejected,'espec_index'):parse_encoding(self.mutate_page('e',0,16,b'\0\0\0\x06'))
 def test_terminal_marker_exact_and_last(self):
  h,ct,cd,et,ed=self.layout();rows=self.e['pages'][-1]['records'];self.assertTrue(self.e['pages'][-1]['terminal_sentinel'])
  with self.assertRaises(Rejected):parse_encoding(self.mutate_page('e',h[7]-1,rows*25+19,b'\xfe'))
  with self.assertRaises(Rejected):parse_encoding(self.mutate_page('e',0,25,b'\0'*16+b'\xff'*4+b'\0'*5))
 def test_header_bounds_truncation_and_binary_footer(self):
  for b in (self.b[:10],b'XX'+self.b[2:],self.b[:22],self.b+b'\0',self.b+b'\xff',self.b*(1048576//len(self.b)+1)):
   with self.assertRaises(ValueError):parse_encoding(b)
 def test_tag_unused_bits_do_not_create_files(self):
  i=copy.deepcopy(self.i);original=a.membership(i);mask=bytearray.fromhex(i['tags'][0]['mask_hex']);mask[-1]^=1;i['tags'][0]['mask_hex']=mask.hex();self.assertEqual(original,a.membership(i));self.assertEqual(len(original),1157)
 def test_tag_bad_length_or_duplicate_rejected(self):
  i=copy.deepcopy(self.i);i['tags'].append(i['tags'][0])
  with self.assertRaises(Rejected):a.membership(i)
  i=copy.deepcopy(self.i);i['tags'][0]['mask_hex']+='00'
  with self.assertRaises(Rejected):a.membership(i)
 def test_root_size_mismatch_blocks_consistency(self):
  d=copy.deepcopy(self.d);d['entries'][0]['encoded_bytes']+=1;s,_,_=self.reconcile(d=d);self.assertEqual(s['reconciliation_status'],'unresolved');self.assertTrue(s['download_metadata_issues'])
 def test_install_size_mismatch_is_not_approved(self):
  i=copy.deepcopy(self.i);i['entries'][0]['decoded_bytes']+=1
  try:s,rows,c=self.reconcile(i=i)
  except Rejected:return # Independent cross-check may stop before emitting an incomplete candidate set.
  self.assertEqual(s['reconciliation_status'],'unresolved');self.assertTrue(s['mapping_issues'])
 def test_changed_fixture_cannot_reuse_old_pins(self):
  original=a.load;f=copy.deepcopy(original('public-fixtures.json'));name=next(r['snapshot'].split('/')[-1] for r in self.objects['requests'] if r['kind']=='encoding');b=bytearray(base64.b64decode(f['objects'][name]['base64']));b[-1]^=1;f['objects'][name]['base64']=base64.b64encode(b).decode()
  with patch.object(a,'load',side_effect=lambda name:f if name=='public-fixtures.json' else original(name)):
   with self.assertRaisesRegex(Rejected,'source_encoded_binding'):a.inputs()
 def test_no_runtime_approval_and_unresolved_semantics_visible(self):
  s,_,c=self.reconcile();self.assertEqual(s['new_battlenet_requests'],0);self.assertFalse(s['payload_downloaded']);self.assertFalse(s['installer_executed']);self.assertFalse(s['production_catalog_modified']);self.assertEqual(s['runtime_approved_entries'],0);self.assertFalse(s['selection_policy']['final_install_plan']);self.assertFalse(s['selection_policy']['volatile_semantics_resolved']);self.assertFalse(s['footer_semantics_interpreted']);self.assertFalse(s['agent_dependency_resolved'])
 def test_legacy_broker_rejects_review_only_data(self):
  _,_,c=self.reconcile();r=a.legacy_compatibility(c);self.assertTrue(r['review_schema_rejected']);self.assertEqual(r['rejection_code'],'policy_shape');self.assertFalse(r['candidate_host_allowed_by_g37']);self.assertFalse(r['within_existing_resource_count_limit']);self.assertFalse(r['limits_modified'])
 def test_offline_codec_source_parity(self):
  old=(a.G43/'analysis-tools/public-manifest-g43/manifests.py').read_text();new=(Path(__file__).parent/'codec.py').read_text();ot=ast.parse(old);nt=ast.parse(new)
  for name in ('decode_blte','Reader','tags','parse_install','parse_download'):
   o=next(n for n in ot.body if getattr(n,'name',None)==name);n=next(n for n in nt.body if getattr(n,'name',None)==name);self.assertEqual(ast.dump(o),ast.dump(n))
if __name__=='__main__':unittest.main()
