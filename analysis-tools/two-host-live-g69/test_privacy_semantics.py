import json
import unittest
from privacy_semantics import ResponseRelation, ua_structure, table_sequences
from semantic_audit import Audit

BODY = b'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0\nagent|1234567|\n'

def framed(body=BODY, status=b'200 OK', extra=b''):
    return b'HTTP/1.1 '+status+b'\r\nContent-Length: '+str(len(body)).encode()+b'\r\n'+extra+b'\r\n'+body

class T(unittest.TestCase):
    def test_split_response_every_boundary(self):
        data = framed()
        for split in range(len(data)+1):
            r = ResponseRelation()
            r.note_query('a', '1234567', '/v2/summary')
            r.feed('a', data[:split]);r.feed('a', data[split:])
            row = r.report()['rows'][0]
            self.assertTrue(row['matches_sequence_in_complete_200_table_on_same_TLS_context'])
            self.assertNotIn('1234567', json.dumps(r.report()))

    def test_chunked_every_boundary(self):
        data = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'+hex(len(BODY))[2:].encode()+b'\r\n'+BODY+b'\r\n0\r\n\r\n'
        for split in range(len(data)+1):
            r = ResponseRelation();r.note_query('a','1234567','/v2/summary')
            r.feed('a',data[:split]);r.feed('a',data[split:])
            self.assertTrue(r.report()['rows'][0]['matches_sequence_in_complete_200_table_on_same_TLS_context'])

    def test_two_responses_with_incomplete_second(self):
        r=ResponseRelation()
        r.feed('a',framed()+b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
        self.assertEqual(r.counts['complete_framed_responses'],1)
        self.assertGreater(r.report()['buffered_bytes'],0)

    def test_wrong_context(self):
        r=ResponseRelation();r.note_query('b','1234567','/v2/summary');r.feed('a',framed())
        self.assertFalse(r.report()['rows'][0]['matches_sequence_in_complete_200_table_on_same_TLS_context'])

    def test_not_a_recognized_table(self):
        self.assertEqual(table_sequences(b'# seqn = 1234567\nprivate stuff'),(set(),False))

    def test_version_table_seqn_comment(self):
        seqs,valid=table_sequences(b'Name!STRING:0|BuildConfig!HEX:16\n# seqn = 1234567\n')
        self.assertTrue(valid);self.assertEqual(seqs,{'1234567'})

    def test_zero_is_not_automatically_benign(self):
        r=ResponseRelation();r.note_query('a','0','/v2/summary')
        row=r.report()['rows'][0]
        self.assertTrue(row['is_zero_sentinel_candidate_not_proven'])
        self.assertEqual(row['meaning'],'unknown_requires_more_evidence')

    def test_reject_ambiguous_framing(self):
        for extra in [b'Transfer-Encoding: chunked\r\n',b'Content-Length: 1\r\n',b'Content-Encoding: gzip\r\n']:
            r=ResponseRelation();r.feed('a',framed(extra=extra))
            self.assertIn('a',r.blocked);self.assertFalse(r.sequence_sets)

    def test_bad_status_not_sequence_source(self):
        r=ResponseRelation();r.feed('a',framed(status=b'404 Not Found'))
        self.assertFalse(r.sequence_sets)

    def test_public_relation_not_global_clearance(self):
        r=ResponseRelation(['@seq:1234567']);r.note_query('a','1234567','/v2/summary')
        self.assertTrue(r.report()['rows'][0]['matches_prepared_public_sequence_exact'])
        self.assertFalse(r.report()['rows'][0]['fingerprinting_absence_proven'])

    def test_fixed_prefix_not_ignored(self):
        u=ua_structure('Blizzard Agent/1.2.3.4',['1.2.3.4'])
        self.assertTrue(u['exact_fixed_product_version_grammar'])
        self.assertTrue(u['only_fixed_words_public_versions_and_separators_observed'])

    def test_secret_text_never_exported(self):
        s='Agent/1.2.3.4 SECRET-DEVICE-NAME (987654321)'
        u=ua_structure(s,['1.2.3.4']);encoded=json.dumps(u)
        self.assertNotIn('SECRET',encoded);self.assertNotIn('987654321',encoded)
        self.assertNotIn('1.2.3.4',encoded);self.assertGreater(u['unresolved_token_count'],0)
        self.assertFalse(u['exact_fixed_product_version_grammar'])

    def test_numeric_opaque_version_not_public(self):
        u=ua_structure('Agent/89.76.54.32')
        self.assertFalse(u['all_version_shapes_match_public_reference'])
        self.assertFalse(u['fingerprinting_absence_proven'])

    def test_integration_keeps_raw_values_only_in_memory(self):
        a=Audit()
        a.feed('a',b'GET /v2/summary?seqn=1234567 HTTP/1.1\r\nHost: us.version.battle.net\r\nUser-Agent: Blizzard Agent/1.2.3\r\n\r\n')
        a.responses.feed('a',framed())
        out=a.report()
        self.assertTrue(out['query_response_relation']['rows'][0]['matches_sequence_in_complete_200_table_on_same_TLS_context'])
        self.assertNotIn('1234567',json.dumps(out))
        self.assertNotIn('1.2.3',json.dumps(out))

    def test_ua_cap(self):
        u=ua_structure('SECRET'*1000)
        self.assertTrue(u['truncated']);self.assertEqual(u['structure'],[])

    def test_actual_double_hash_marker(self):
        body=b'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0\n## seqn = 9876543\nagent|1234567|\n'
        seqs,ok=table_sequences(body)
        self.assertTrue(ok)
        self.assertEqual(seqs,{'9876543','1234567'})
        r=ResponseRelation(['@seq:9876543','@summaryseq:9876543'])
        r.note_query('a','9876543','/v2/summary')
        r.feed('a',framed(body))
        row=r.report()['rows'][0]
        self.assertTrue(row['matches_prepared_public_summary_document_sequence_exact'])
        self.assertTrue(row['matches_summary_document_sequence_on_same_TLS_context'])
        self.assertNotIn('9876543',json.dumps(r.report()))

    def test_table_row_not_summary_document_sequence(self):
        body=b'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0\n## seqn = 9876543\nagent|1234567|\n'
        r=ResponseRelation()
        r.note_query('a','1234567','/v2/summary');r.feed('a',framed(body))
        row=r.report()['rows'][0]
        self.assertTrue(row['matches_sequence_in_complete_200_table_on_same_TLS_context'])
        self.assertFalse(row['matches_summary_document_sequence_on_same_TLS_context'])

    def test_fixed_installer_literal_whole_value(self):
        u=ua_structure('phoenix-agent/1.0')
        self.assertTrue(u['exact_match_to_pinned_official_bootstrap_static_UA'])
        for s in ('phoenix-agent/1.0 SECRET','phoenix-agent/1.0.1','Phoenix-agent/1.0'):
            self.assertFalse(ua_structure(s)['exact_match_to_pinned_official_bootstrap_static_UA'])

    def test_public_reference_loader_double_hash(self):
        import tempfile
        from pathlib import Path
        from semantic_audit import load_public
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'public-reference.PRIVATE.json').write_text(json.dumps({'rows':[{
                'route':'/v2/summary','status':200,
                'text':'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0\n## seqn = 9876543\nagent|1234567|\n'
            }]}))
            tokens,report=load_public(root)
            self.assertIn('@seq:9876543',tokens)
            self.assertIn('@summaryseq:9876543',tokens)
            self.assertIn('@seq:1234567',tokens)
            self.assertNotIn('@summaryseq:1234567',tokens)
            self.assertNotIn('9876543',json.dumps(report))