import json,os,random,struct,subprocess,unittest
from pathlib import Path
import patch_audit as a
import agent_sequence_visibility as m
ORACLE=Path(os.environ.get('SEQUENCE_VISIBILITY_ORACLE','/missing'))
class SequenceModel(unittest.TestCase):
    def test_unknown_field(self):
        with self.assertRaises(a.AuditError):m.predict(guessed_field=1)
    def test_u32_types_bounds(self):
        for v in (-1,2**32,True,None,'2'):
            with self.subTest(v=v),self.assertRaises(a.AuditError):m.predict(header=v)
    def test_operation_mode_bucket_count_bounds(self):
        for k,v in [('operation',3),('mode',6),('bucket',16),('count',2)]:
            with self.subTest(k=k),self.assertRaises(a.AuditError):m.predict(**{k:v})
    def test_modes_skip_refresh(self):
        for mode in (2,4,5):
            out=m.predict(mode=mode);self.assertEqual(out['events'],[]);self.assertEqual(out['cache_after'],1)
    def test_equal_no_open_or_bind(self):
        out=m.predict(header=2,cached=2,bind_error=73);self.assertEqual(out['return_code'],0);self.assertEqual(out['events'],[])
    def test_unsigned_backwards_rejected(self):
        out=m.predict(header=0,cached=0xffffffff);self.assertEqual(out['return_code'],1);self.assertEqual(out['events'],[11])
    def test_open_failure_keeps_cache(self):
        out=m.predict(open_error=73);self.assertEqual(out['return_code'],73);self.assertEqual(out['cache_after'],1);self.assertEqual(out['bind_calls'],0)
    def test_reader_bind_failure_returns_zero(self):
        out=m.predict(bind_error=73);self.assertEqual(out['return_code'],0);self.assertEqual(out['cache_after'],2);self.assertEqual(out['bind_calls'],1)
    def test_second_refresh_does_not_retry_failed_bind(self):
        out=m.predict(operation=2,bind_error=73);self.assertEqual(out['first_reader_return'],0);self.assertEqual(out['return_code'],0);self.assertEqual(out['open_calls'],out['bind_calls']);self.assertEqual(out['bind_calls'],1)
    def test_writer_bind_failure_does_not_publish_header(self):
        out=m.predict(operation=0,header=1,bind_error=73);self.assertEqual(out['return_code'],73);self.assertEqual(out['header_after'],1);self.assertEqual(out['cache_after'],2)
    def test_writer_failures_before_bind_keep_both_old(self):
        for stage in ('temp_error','serialize_error','flush_error'):
            out=m.predict(operation=0,header=1,**{stage:73});self.assertEqual((out['header_after'],out['cache_after']),(1,1));self.assertEqual(out['bind_calls'],0)
    def test_writer_success_updates_header_only_after_bind(self):
        out=m.predict(operation=0,header=1);self.assertEqual(out['header_seen_at_bind'],1);self.assertEqual(out['cache_seen_at_bind'],2);self.assertEqual(out['header_after'],2)
    def test_serializer_full_partial_same_control_result(self):
        self.assertEqual(m.predict(operation=0,count=0),m.predict(operation=0,count=1))
    def test_skipped_mode_zero_is_not_binding_proof(self):
        out=m.predict(mode=5,open_error=73,bind_error=73);self.assertEqual(out['return_code'],0);self.assertEqual(out['bind_calls'],0)

@unittest.skipUnless(ORACLE.is_file(),'built isolated nonthrowing mocked-I/O fragment harness required')
class SequenceFragments(unittest.TestCase):
    def compare(self,**kwargs):return m.compare(ORACLE,**kwargs)['observed']
    def test_writer_all_buckets(self):
        for bucket in range(16):
            out=self.compare(operation=0,bucket=bucket,header=1);self.assertEqual(out['bind_bucket'],bucket);self.assertEqual(out['header_after'],2)
    def test_reader_all_buckets(self):
        for bucket in range(16):
            out=self.compare(bucket=bucket);self.assertEqual(out['filename_bucket'],bucket);self.assertEqual(out['filename_sequence'],2)
    def test_reader_bind_error_zero_return(self):
        out=self.compare(bind_error=73);self.assertEqual(out['return_code'],0);self.assertEqual(out['events'],[7,8,9,4,5,13,11,6])
    def test_second_call_skips_after_failed_bind(self):
        out=self.compare(operation=2,bind_error=73);self.assertEqual(out['bind_calls'],1);self.assertEqual(out['open_calls'],1);self.assertEqual(out['first_reader_return'],0)
    def test_writer_failure_stage_matrix(self):
        for field in ('temp_error','serialize_error','flush_error','bind_error'):
            for code in (1,73,0xffffffff):
                out=self.compare(operation=0,header=1,**{field:code});self.assertEqual(out['header_after'],1);self.assertEqual(out['return_code'],code)
    def test_writer_bind_failure_cache_ahead(self):
        out=self.compare(operation=0,header=1,bind_error=73);self.assertEqual(out['cache_after'],2);self.assertEqual(out['header_seen_at_bind'],1)
    def test_reader_skip_modes_with_errors(self):
        for mode in (2,4,5):
            out=self.compare(mode=mode,open_error=73,bind_error=73);self.assertEqual(out['events'],[])
    def test_equal_header_cache_has_no_helper_calls(self):
        for value in (0,1,0x80000000,0xffffffff):self.assertEqual(self.compare(header=value,cached=value)['events'],[])
    def test_reverse_order_is_unsigned(self):
        for cached,header in ((2,1),(0xffffffff,0),(0x80000000,0x7fffffff)):
            out=self.compare(cached=cached,header=header);self.assertEqual(out['return_code'],1);self.assertEqual(out['open_calls'],0)
    def test_forward_unsigned_extremes(self):
        for cached,header in ((0,1),(0,0xffffffff),(0x7fffffff,0x80000000)):
            out=self.compare(cached=cached,header=header);self.assertEqual(out['filename_sequence'],header)
    def test_both_serializer_calls(self):
        for count in (0,1):self.assertEqual(self.compare(operation=0,header=1,count=count)['return_code'],0)
    def test_256_deterministic_vectors(self):
        rng=random.Random(982471)
        for i in range(256):
            self.compare(operation=rng.randrange(3),mode=rng.randrange(6),bucket=rng.randrange(16),header=rng.getrandbits(32),cached=rng.getrandbits(32),next_sequence=rng.getrandbits(32),count=rng.randrange(2),**{k:rng.choice((0,0,0,1,73,0xffffffff)) for k in ('temp_error','serialize_error','flush_error','bind_error','open_error')})
    def test_memory_canaries_for_edge_slots(self):
        for bucket in (0,15):
            for op in (0,1,2):self.assertTrue(self.compare(bucket=bucket,operation=op)['memory_canaries_intact'])
    def test_native_protocol_rejects_invalid_inputs(self):
        valid=[m.DEFAULTS[k] for k in m.FIELDS]
        bodies=[b'',b'x'*47,b'x'*49]
        for field,value in ((0,3),(1,6),(2,16),(11,2)):
            bad=valid.copy();bad[field]=value;bodies.append(struct.pack('<12I',*bad))
        for data in bodies:
            run=subprocess.run([str(ORACLE)],input=data,capture_output=True,timeout=5);self.assertEqual(run.returncode,90);self.assertEqual(run.stdout,b'')
    def test_build_receipt_has_no_windows_execution_claim(self):
        receipt=json.loads((ORACLE.parent/'BUILD-RECEIPT.json').read_text());self.assertEqual(len(receipt['fragments']),4);self.assertTrue(receipt['all_original_fragment_elf_bytes_verified']);self.assertFalse(receipt['windows_apis_executed']);self.assertFalse(receipt['installation_ready'])
    def test_comparison_labels_mocked_boundary(self):
        got=m.compare(ORACLE);self.assertTrue(got['external_helpers_mocked']);self.assertTrue(got['original_agent_function_fragments_executed']);self.assertFalse(got['windows_agent_process_executed'])
