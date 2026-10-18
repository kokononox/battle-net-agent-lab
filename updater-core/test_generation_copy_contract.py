import copy,dataclasses,json,struct,unittest
from generation_copy_contract import GenerationCopy,review_copies,MAX_ROUND_BYTES
from release_core import InvalidRelease
from lookup3 import hashlittle2
from test_copied_control import fixture as control_fixture
from test_local_candidates import fixture as v7_fixture
from test_local_v8 import fixture as v8_fixture
from test_installed_identity import info,CONFIG
from test_installed_preferences import BASE

def index_bytes(bucket,version=7):
 raw=bytearray(v7_fixture()[-1]if version==7 else v8_fixture())
 raw[10]=bucket;raw[4:8]=hashlittle2(bytes(raw[8:24]))[0].to_bytes(4,'little');return bytes(raw)
def fixture(protocol=5,ext=False,version=7,state=1):
 control,names=control_fixture(protocol,ext,state)
 return GenerationCopy(info(tags=BASE),CONFIG,control,tuple(names),{name:index_bytes(i,version)for i,name in enumerate(names)})
class ContractTests(unittest.TestCase):
 def r(self,c=None,d=None):
  c=fixture()if c is None else c;return review_copies(c,copy.deepcopy(c)if d is None else d)
 def bad(self,c,code=None):
  with self.assertRaisesRegex(InvalidRelease,code or'.*'):self.r(c)
 def test_v7_stable_bundle(self):
  r=self.r();self.assertTrue(r['copied_bundle_consistency_checked']);self.assertEqual(r['selected_index_files'],16);self.assertEqual(r['index_family'],7)
 def test_v8_stays_opaque(self):
  r=self.r(fixture(version=8));self.assertTrue(all(x['v8_location_qwords_remain_opaque']for x in r['index_observations']));self.assertIn('v8_archive_location_fields_opaque',r['blockers'])
 def test_v4_profile(self):self.assertEqual(self.r(fixture(protocol=4))['control_profile']['protocol'],4)
 def test_extension_is_blocker_not_qualified(self):self.assertIn('control_extension_semantics_unqualified',self.r(fixture(ext=True))['blockers'])
 def test_private_control_name_not_exported(self):
  s=json.dumps(self.r());self.assertNotIn('Private',s);self.assertNotIn('Global',s)
 def test_private_baseline_terms_not_exported(self):
  c=fixture();c=dataclasses.replace(c,info=info(tags=BASE.replace('speech?','speech? acct-SECRET?')));self.assertNotIn('SECRET',json.dumps(self.r(c)))
 def test_baseline_round_change_stops(self):
  c=fixture();d=dataclasses.replace(c,info=c.info+b'\n')
  with self.assertRaisesRegex(InvalidRelease,'baseline_changed'):self.r(c,d)
 def test_config_round_change_stops(self):
  c=fixture();d=dataclasses.replace(c,config=c.config+b'\n')
  with self.assertRaisesRegex(InvalidRelease,'baseline_changed'):self.r(c,d)
 def test_control_round_change_stops(self):
  c=fixture();raw=bytearray(c.control);raw[-1]=1;d=dataclasses.replace(c,control=bytes(raw))
  with self.assertRaisesRegex(InvalidRelease,'control_changed'):self.r(c,d)
 def test_index_round_change_stops(self):
  c=fixture();d=copy.deepcopy(c);name=next(iter(d.indexes));raw=bytearray(d.indexes[name]);raw[44]^=1;d.indexes[name]=bytes(raw)
  with self.assertRaisesRegex(InvalidRelease,'index_bytes_changed'):self.r(c,d)
 def test_inventory_order_is_not_identity(self):
  c=fixture();d=dataclasses.replace(c,inventory=c.inventory[::-1]);self.assertEqual(self.r(c,d)['bundle_sha256'],self.r(c)['bundle_sha256'])
 def test_inventory_added_between_rounds_stops(self):
  c=fixture();d=dataclasses.replace(c,inventory=c.inventory+('000000ffff.idx',))
  with self.assertRaisesRegex(InvalidRelease,'inventory_changed'):self.r(c,d)
 def test_newer_filename_not_selected(self):
  c=fixture();c=dataclasses.replace(c,inventory=c.inventory+('000000ffff.idx',));r=self.r(c);self.assertEqual(r['index_observations'][0]['member'],'0000000000.idx');self.assertTrue(r['index_observations'][0]['newer_inventory_member_ignored']);self.assertFalse(r['newer_filename_fallback_used'])
 def test_missing_referenced_inventory_member(self):
  c=fixture();self.bad(dataclasses.replace(c,inventory=c.inventory[1:]+('000000ffff.idx',)),'referenced_index_missing')
 def test_wrong_selected_file_not_replaced_by_newer(self):
  c=fixture();idx=dict(c.indexes);idx['000000ffff.idx']=idx.pop('0000000000.idx');self.bad(dataclasses.replace(c,indexes=idx),'index_set_not_control_referenced')
 def test_only_fifteen_indexes_refused(self):
  c=fixture();idx=dict(c.indexes);idx.pop(next(iter(idx)));self.bad(dataclasses.replace(c,indexes=idx),'index_count')
 def test_seventeen_indexes_refused(self):
  c=fixture();idx=dict(c.indexes);idx['000000ffff.idx']=next(iter(idx.values()));self.bad(dataclasses.replace(c,indexes=idx),'index_count')
 def test_pending_control_stops_no_recovery(self):self.bad(fixture(state=2),'nonquiescent_research_state')
 def test_reset_state_stops_not_corruption(self):self.bad(fixture(state=0),'nonquiescent_research_state')
 def test_unknown_control_profile(self):
  c=fixture();raw=bytearray(c.control);raw[0]=6;self.bad(dataclasses.replace(c,control=bytes(raw)),'unsupported_control_protocol')
 def test_header_checksum_damage(self):
  c=fixture();idx=dict(c.indexes);name=next(iter(idx));raw=bytearray(idx[name]);raw[4]^=1;idx[name]=bytes(raw);self.bad(dataclasses.replace(c,indexes=idx),'header_checksum')
 def test_index_payload_checksum_damage(self):
  c=fixture();idx=dict(c.indexes);name=next(iter(idx));raw=bytearray(idx[name]);raw[44]^=1;idx[name]=bytes(raw);self.bad(dataclasses.replace(c,indexes=idx),'primary_checksum')
 def test_bucket_mismatch_even_valid_checksum(self):
  c=fixture();idx=dict(c.indexes);idx['0000000000.idx']=index_bytes(1);self.bad(dataclasses.replace(c,indexes=idx),'unsupported_v7_profile')
 def test_unknown_index_version(self):
  c=fixture();idx=dict(c.indexes);raw=bytearray(idx['0000000000.idx']);raw[8]=9;idx['0000000000.idx']=bytes(raw);self.bad(dataclasses.replace(c,indexes=idx),'unknown_index_format')
 def test_mixed_families_stops(self):
  c=fixture();idx=dict(c.indexes);idx['0000000000.idx']=index_bytes(0,8);self.bad(dataclasses.replace(c,indexes=idx),'mixed_index_families')
 def test_nonempty_v8_tail_stops(self):
  c=fixture(version=8);idx=dict(c.indexes);raw=bytearray(idx['0000000000.idx']);raw[-1]=1;idx['0000000000.idx']=bytes(raw);self.bad(dataclasses.replace(c,indexes=idx),'nonempty_or_unknown_tail')
 def test_metadata_identity_mismatch(self):
  with self.assertRaises(ValueError):self.r(dataclasses.replace(fixture(),config=CONFIG+b'bad'))
 def test_oversize_index_refused(self):
  c=fixture();idx=dict(c.indexes);idx['0000000000.idx']=bytes(4*1024**2+1);self.bad(dataclasses.replace(c,indexes=idx),'index_shape')
 def test_oversize_metadata_refused(self):self.bad(dataclasses.replace(fixture(),info=bytes(1048577)),'metadata_budget')
 def test_untyped_claim_dict_not_authority(self):
  with self.assertRaisesRegex(InvalidRelease,'copy_type'):review_copies({'active_generation_proven':True},fixture())
 def test_duplicate_inventory_refused(self):
  c=fixture();self.bad(dataclasses.replace(c,inventory=c.inventory+(c.inventory[0],)),'duplicate_index_inventory')
 def test_unsafe_member_refused_without_echo(self):
  c=fixture();self.bad(dataclasses.replace(c,inventory=c.inventory+('../PRIVATE.idx',)),'index_name_inventory')
 def test_mutable_metadata_refused(self):self.bad(dataclasses.replace(fixture(),control=bytearray(fixture().control)),'metadata_budget')
 def test_unknown_optional_feature_in_baseline_stops(self):
  with self.assertRaises(ValueError):self.r(dataclasses.replace(fixture(),info=info(tags=BASE+' FutureFeature?')))
 def test_all_authority_flags_remain_false(self):
  r=self.r()
  for k in ('no_change_between_rounds_proven','input_round_order_or_capture_times_verified','live_capture_scope_approved','additional_file_read_authorized','fresh_installed_preferences_proven','active_generation_proven','coherent_live_snapshot_proven','local_reuse_authorized','required_set_selected','native_agent_executed','game_access','installation_ready','apply_authorized'):self.assertFalse(r[k])
  self.assertIsNone(r['required_network_download_bytes']);self.assertEqual([r[k]for k in ('filesystem_reads','filesystem_writes','network_requests')],[0,0,0])
 def test_two_equal_rounds_do_not_claim_ABA_protection(self):self.assertIn('sequential_equal_bytes_not_atomic_snapshot_or_ABA_protection',self.r()['blockers'])
 def test_bytes_budget_accounting(self):
  c=fixture();n=len(c.info)+len(c.config)+len(c.control)+sum(map(len,c.indexes.values()));r=self.r(c);self.assertEqual(r['per_round_content_bytes'],n);self.assertEqual(r['two_round_content_bytes'],2*n);self.assertEqual(r['maximum_per_round_content_bytes'],MAX_ROUND_BYTES)
 def test_input_dict_not_modified(self):
  c=fixture();before=copy.deepcopy(c);self.r(c);self.assertEqual(c,before)
 def test_bundle_digest_binds_index_content(self):
  c=fixture();r=self.r(c);d=fixture(version=8);self.assertNotEqual(r['bundle_sha256'],self.r(d)['bundle_sha256'])
 def test_bundle_digest_binds_inventory(self):
  c=fixture();self.assertNotEqual(self.r(c)['bundle_sha256'],self.r(dataclasses.replace(c,inventory=c.inventory+('000000ffff.idx',)))['bundle_sha256'])
if __name__=='__main__':unittest.main()
