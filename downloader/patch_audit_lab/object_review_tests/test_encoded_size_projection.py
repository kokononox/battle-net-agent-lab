"""Exact metadata byte sums, never an estimate of required download bytes."""
from collections import Counter
from unittest.mock import patch
import json,random,unittest
import saved_object_review as o
import source_binding as b
from test_saved_object_review import Integration as Base,raw_manifest,manifest,model_for
from test_pinned_download_model import fixture_tags

class ExactSizes(unittest.TestCase):
    def finish(self,items):
        sizes=o.EncodedSizes();counts=Counter({k:0 for k in o.CATEGORIES})
        for category,lo,hi in items:sizes.add(category,lo,hi);counts[category]+=1
        return sizes.finish(counts,len(items))
    def test_two_metadata_groups_sum(self):
        q=self.finish([(o.CATEGORIES[5],10,10),(o.CATEGORIES[2],30,30)]);self.assertEqual(q['total_selected_unique_encoded_bytes'],40);self.assertEqual(q['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[2]],30)
    def test_conflicting_size_suppresses_total_not_min_or_max(self):
        q=self.finish([(o.CATEGORIES[0],10,11),(o.CATEGORIES[2],20,20)]);self.assertIsNone(q['total_selected_unique_encoded_bytes']);self.assertEqual(q['known_consistent_positive_size_encoded_bytes'],20);self.assertIsNone(q['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[0]])
    def test_zero_size_unresolved_not_valid_zero_total(self):
        q=self.finish([(o.CATEGORIES[1],0,0)]);self.assertIsNone(q['total_selected_unique_encoded_bytes']);self.assertEqual(q['unresolved_unique_ekeys'],1);self.assertIsNone(q['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[1]])
    def test_empty_selection_known_zero_NOT_network_claim(self):
        q=self.finish([]);self.assertEqual(q['total_selected_unique_encoded_bytes'],0);self.assertTrue(q['complete_for_selected_unique_ekeys']);self.assertTrue(q['not_listed_encoded_bytes_are_NOT_required_download_bytes'])
    def test_exact_above_float_integer_precision(self):
        sizes=o.EncodedSizes();size=2**40-1;n=9001
        for _ in range(n):sizes.add(o.CATEGORIES[2],size,size)
        counts=Counter({k:0 for k in o.CATEGORIES});counts[o.CATEGORIES[2]]=n;q=sizes.finish(counts,n)
        expected=n*size;self.assertGreater(expected,2**53);self.assertIs(type(q['total_selected_unique_encoded_bytes']),int);self.assertEqual(q['total_selected_unique_encoded_bytes'],expected);self.assertEqual(json.loads(json.dumps(q))['total_selected_unique_encoded_bytes'],expected)
    def test_largest_five_byte_size_preserved(self):self.assertEqual(self.finish([(o.CATEGORIES[2],2**40-1,2**40-1)])['total_selected_unique_encoded_bytes'],2**40-1)
    def test_out_of_range_size_rejected(self):
        with self.assertRaisesRegex(b.BindingError,'object_encoded_size_aggregation_shape'):self.finish([(o.CATEGORIES[2],2**40,2**40)])
    def test_negative_size_rejected(self):
        with self.assertRaises(b.BindingError):self.finish([(o.CATEGORIES[2],-1,-1)])
    def test_float_size_not_silently_rounded(self):
        with self.assertRaises(b.BindingError):self.finish([(o.CATEGORIES[2],1.0,1.0)])
    def test_boolean_size_not_integer(self):
        with self.assertRaises(b.BindingError):self.finish([(o.CATEGORIES[2],True,True)])
    def test_category_must_be_known(self):
        with self.assertRaises(b.BindingError):self.finish([('PRIVATE_UNKNOWN_CATEGORY',1,1)])
    def test_positive_category_requires_consistent_nonzero_size(self):
        for lo,hi in [(0,0),(1,2)]:
            with self.assertRaises(b.BindingError):self.finish([(o.CATEGORIES[2],lo,hi)])
    def test_count_reconciliation_required(self):
        sizes=o.EncodedSizes();sizes.add(o.CATEGORIES[2],1,1)
        with self.assertRaisesRegex(b.BindingError,'object_encoded_byte_reconciliation'):sizes.finish(Counter({k:0 for k in o.CATEGORIES}),1)
    def test_no_framing_decoded_size_or_download_claim(self):
        q=self.finish([(o.CATEGORIES[2],5,5)]);self.assertTrue(q['archive_headers_padding_or_transfer_framing_not_added']);self.assertFalse(q['decoded_install_size_computed']);self.assertNotIn('required_network_download_bytes',q);self.assertIn('NOT_record_multiplicity',q['counting_unit'])

class SizeIntegration(unittest.TestCase):
    setUpClass=classmethod(Base.setUpClass.__func__)
    setUp=Base.setUp;tearDown=Base.tearDown;rebind_test_manifest=Base.rebind_test_manifest
    prepare=Base.prepare;execute=Base.execute;candidate=Base.candidate;assert_no_work=Base.assert_no_work
    def sizes(self,q):return q['object_projection']['encoded_size_projection']
    def test_duplicate_key_size_counted_once(self):
        model=self.prepare();q,_=self.execute(model);z=self.sizes(q);self.assertEqual(z['total_selected_unique_encoded_bytes'],160);self.assertEqual(z['known_consistent_positive_size_unique_ekeys'],3);self.assertTrue(q['diagnostic_projection']['selected_encoded_bytes_computed'])
    def test_matching_wrong_size_and_unlisted_byte_groups(self):
        model=self.prepare();self.candidate(1,10);self.candidate(7,999);q,_=self.execute(model);z=self.sizes(q);states=z['metadata_encoded_bytes_by_inventory_state'];self.assertEqual(states[o.CATEGORIES[5]],10);self.assertEqual(states[o.CATEGORIES[3]],70);self.assertEqual(states[o.CATEGORIES[2]],80);self.assertEqual(z['total_selected_unique_encoded_bytes'],160)
    def test_bad_coordinates_size_stays_in_its_own_group(self):
        model=self.prepare();self.candidate(7,70,offset=9999);q,_=self.execute(model);self.assertEqual(self.sizes(q)['metadata_encoded_bytes_by_inventory_state'][o.CATEGORIES[4]],70)
    def test_conflict_partial_total_not_published_as_complete(self):
        model=self.prepare([(1,10),(1,11),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);q,_=self.execute(model);z=self.sizes(q);self.assertFalse(q['object_projection']['unique_encoded_size_total_computed']);self.assertFalse(q['diagnostic_projection']['selected_encoded_bytes_computed']);self.assertIsNone(z['total_selected_unique_encoded_bytes']);self.assertEqual(z['known_consistent_positive_size_encoded_bytes'],150)
    def test_zero_partial_total_remains_unknown(self):
        model=self.prepare([(1,0),(1,0),(3,30),(4,40),(5,50),(6,60),(7,70),(8,80)]);q,_=self.execute(model);z=self.sizes(q);self.assertIsNone(z['total_selected_unique_encoded_bytes']);self.assertEqual(z['known_consistent_positive_size_encoded_bytes'],150)
    def test_aliases_do_not_multiply_encoded_bytes(self):
        model=self.prepare();self.candidate(1,10);self.candidate(1,10);q,_=self.execute(model);self.assertEqual(self.sizes(q)['total_selected_unique_encoded_bytes'],160)
    def test_no_network_size_or_health_promotion(self):
        model=self.prepare();q,_=self.execute(model);self.assertIsNone(q['required_network_download_bytes']);self.assertIsNone(q['object_projection']['required_network_download_bytes']);self.assertFalse(q['installation_ready']);self.assertFalse(q['fresh_local_content_verified']);self.assertFalse(q['actual_required_install_set_known']);self.assertEqual(q['scope']['archive_payload_bytes_read'],0);self.assertEqual(q['network_requests'],0);self.assert_no_work()
    def test_empty_selection_reports_zero_not_install_readiness(self):
        raw=manifest(version=1,tags=fixture_tags({'enUS':0,'frFR':255}));self.rebind_test_manifest(raw);self.path.write_bytes(raw);q,_=self.execute(model_for(raw));self.assertEqual(self.sizes(q)['total_selected_unique_encoded_bytes'],0);self.assertEqual(q['object_projection']['unique_ekeys'],0);self.assertFalse(q['installation_ready']);self.assertIsNone(q['required_network_download_bytes'])
    def test_missing_cache_no_size_fallback(self):
        q,_=self.execute(None);self.assertIsNone(q['object_projection']);self.assertIsNone(q['required_network_download_bytes'])
    def test_random_dictionary_oracle_bytes_and_partial_unknowns(self):
        rng=random.Random(7039103)
        for case in range(64):
            entries=[(rng.randint(1,5),rng.randint(0,4)) for _ in range(8)];model=self.prepare(entries);self.f.edit(self.f.inv,'DELETE FROM candidates WHERE id>1')
            groups={}
            for index in (0,1,6,7):key,size=entries[index];groups.setdefault(key,set()).add(size)
            expected={k:0 for k in o.CATEGORIES};known=0;unresolved=0
            for key,values in groups.items():
                if len(values)>1:expected[o.CATEGORIES[0]]=None;unresolved+=1
                elif next(iter(values))==0:expected[o.CATEGORIES[1]]=None;unresolved+=1
                else:
                    size=next(iter(values));known+=size;listed=bool(rng.randrange(2));category=o.CATEGORIES[5] if listed else o.CATEGORIES[2];expected[category]+=size
                    if listed:self.candidate(key,size)
            q,_=self.execute(model,output=self.root/('size-case-'+str(case)));z=self.sizes(q)
            self.assertEqual(z['known_consistent_positive_size_encoded_bytes'],known);self.assertEqual(z['unresolved_unique_ekeys'],unresolved);self.assertEqual(z['metadata_encoded_bytes_by_inventory_state'],expected);self.assertEqual(z['total_selected_unique_encoded_bytes'],None if unresolved else known)
    def test_join_count_change_prevents_publication(self):
        model=self.prepare();original=o.join_inventory
        def inconsistent(*args,**kwargs):
            q=original(*args,**kwargs);q['unique_ekeys_by_metadata_state'][o.CATEGORIES[2]]+=1;return q
        with patch.object(o,'join_inventory',side_effect=inconsistent):
            with self.assertRaisesRegex(b.BindingError,'object_join_unique_count_conflict'):self.execute(model)
        self.assert_no_work();self.assertFalse((self.root/'new/Report').exists())

del Base
