import copy,unittest
from release_core import InvalidRelease
from policy_ambiguity import audit_membership,audit_install_variants,first_indices
import test_selection_policy as fixtures
class AmbiguityTests(unittest.TestCase):
 def audit(self,tags=None,mask=b'\xa0',count=8):return audit_membership(fixtures.tags()if tags is None else tags,count,mask)
 def bad(self,fn,*args):
  with self.assertRaises(InvalidRelease):fn(*args)
 def entries(self):return [(0,'Dir\\File',b'a'*16,10),(1,'dir/file',b'b'*16,11)]
 def test_partition_crossfoot(self):self.assertEqual(sum(x['records']for x in self.audit()['feature_partitions'][0]['cells']),8)
 def test_partition_members(self):self.assertEqual([x['records']for x in self.audit()['feature_partitions'][0]['cells']],[6,0,1,1])
 def test_samples_resolve_cell(self):
  for c in self.audit()['feature_partitions'][0]['cells']:
   for i in c['sample_indices']:self.assertEqual(bool(0xa0&(0x80>>i)),c['candidate_selected']);self.assertEqual(bool(0x80&(0x80>>i)),c['tag_member'])
 def test_sample_bound(self):self.assertEqual(first_indices(255,8),[0,1])
 def test_empty_sample(self):self.assertEqual(first_indices(0,8),[])
 def test_tail_padding_not_sampled(self):self.assertEqual(first_indices(1,1),[])
 def test_candidate_padding_refused(self):self.bad(self.audit,[(0,'Windows',1,b'\xff')],b'\x81',1)
 def test_wrong_bitmap_width(self):self.bad(self.audit,None,b'\xff\xff')
 def test_bool_record_count(self):self.bad(self.audit,None,b'\xff',True)
 def test_unknown_kind(self):self.bad(self.audit,[(0,'x',999,b'\xff')])
 def test_no_features_not_qualification(self):r=self.audit(fixtures.tags()[:-1]);self.assertEqual(r['feature_partitions'],[]);self.assertFalse(r['vendor_selection_policy_qualified'])
 def test_untagged_not_implicitly_required(self):
  r=self.audit([(0,'Windows',1,b'\x80')],b'\x80');self.assertEqual(r['unassigned_dimensions'][0]['records_without_any_tag_of_kind'],7);self.assertFalse(r['unassigned_dimensions'][0]['untagged_semantics_qualified'])
 def test_untagged_selected_audited(self):self.assertEqual(self.audit([(0,'Windows',1,b'\x80')],b'\xff')['unassigned_dimensions'][0]['candidate_selected_without_any_tag_of_kind'],7)
 def test_no_mutation(self):t=fixtures.tags();before=copy.deepcopy(t);self.audit(t);self.assertEqual(t,before)
 def test_zero_selected_stays_unqualified(self):r=self.audit(mask=b'\0');self.assertEqual(r['candidate_records'],0);self.assertFalse(r['required_set_selected']);self.assertIsNone(r['required_network_download_bytes'])
 def test_variant_group_no_choice(self):
  r=audit_install_variants(self.entries(),b'\x80');g=r['groups'][0];self.assertEqual(g['distinct_content_identities'],2);self.assertEqual(g['candidate_selected_records'],1);self.assertIsNone(g['chosen_variant'])
 def test_same_content_duplicate_still_recorded(self):e=self.entries();e[1]=(1,'dir/file',b'a'*16,10);self.assertEqual(audit_install_variants(e,b'\xc0')['groups'][0]['distinct_content_identities'],1)
 def test_variant_row_order_refused(self):e=self.entries();e[1]=(0,*e[1][1:]);self.bad(audit_install_variants,e,b'\xc0')
 def test_variant_row_limit(self):e=[(i,'same',b'a'*16,i)for i in range(12)];g=audit_install_variants(e,b'\xff\xf0')['groups'][0];self.assertEqual(len(g['records']),8);self.assertEqual(g['omitted_records'],4)
 def test_group_limit(self):
  e=[(i,str(i//2),b'a'*16,10)for i in range(36)];r=audit_install_variants(e,b'\xff'*4+b'\xf0');self.assertEqual(len(r['groups']),16);self.assertEqual(r['omitted_groups'],2)
 def test_not_install_path_authority(self):e=[(i,'../same',b'a'*16,10)for i in range(2)];r=audit_install_variants(e,b'\xc0');self.assertIn('NOT Windows path safety',r['normalization']);self.assertFalse(r['variant_choice_policy_qualified'])
 def test_duplicate_tag_refused(self):self.bad(self.audit,[(0,'Windows',1,b'\xff'),(1,'Windows',1,b'\xff')])
class AuditIntegrationTests(unittest.TestCase):
 setUp=fixtures.Integration.setUp
 def run_review(self):
  from policy_ambiguity_review import review
  return review(self.base,self.objects,self.plan,fixtures.PROFILE)
 def test_full_identity_chain(self):r=self.run_review();self.assertEqual(r['target']['version'],'19.1.0.99000');self.assertTrue(r['independent_ordinal_checks_passed']);self.assertFalse(r['required_set_selected'])
 def test_no_candidate_mutation(self):
  before={p.name:p.read_bytes()for p in self.plan.iterdir()};self.run_review();self.assertEqual(before,{p.name:p.read_bytes()for p in self.plan.iterdir()})
 def test_sample_identity(self):
  r=self.run_review();q=r['download']['feature_partitions'][0];samples=[s for c in q['cells']for s in c['samples']];self.assertEqual(samples[0]['ekey'],fixtures.EK.hex())
 def test_corrupt_source_refused(self):
  p=self.objects/'download.decoded';p.write_bytes(p.read_bytes()+b'x')
  with self.assertRaises(InvalidRelease):self.run_review()
 def test_plan_mismatch_refused(self):
  p=self.plan/'CANDIDATE-PLAN.sqlite';p.write_bytes(p.read_bytes()+b'x')
  with self.assertRaises(InvalidRelease):self.run_review()
