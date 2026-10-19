import base64,json
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from request_audit import *
from http_input import parse_requests

class AuditTests(unittest.TestCase):
    def request(self,body=b'',extra=b'',target=b'/tpr/file'):
        return b'GET '+target+b' HTTP/1.1\r\nHost: level3.blizzard.com\r\nUser-Agent: PRIVATE_AGENT\r\n'+extra+b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    def add(self,a,raw,seq=1,channel='s1',accepted='auto',truncated=False):
        a.add(1,dict(socket=channel,sequence=seq,declared_bytes=len(raw),accepted_bytes=len(raw) if accepted=='auto' else accepted,truncated=truncated),raw)
    def test_zero_body_not_zero_personal_proof(self):
        a=AuditBuffer(None);self.add(a,self.request());r=validate_audit(a.finish());self.assertEqual(r['summary']['target_requests'],1);self.assertFalse(r['zero_personal_data_proven']);self.assertEqual(r['summary']['target_nonzero_body_requests'],0)
    def test_split_header_and_body_sorted(self):
        a=AuditBuffer(b'PRIVATE_CPU');raw=self.request(b'{"cpu":"PRIVATE_CPU"}');cut=len(raw)-5
        self.add(a,raw[cut:],2);self.add(a,raw[:cut]);r=a.finish()['requests'][0]
        self.assertTrue(r['cpu_literal_match']);self.assertTrue(r['body_complete']);self.assertEqual(r['body_field_hints'],['cpu'])
    def test_no_raw_url_headers_values_hashes(self):
        a=AuditBuffer(b'PRIVATE_CPU');self.add(a,self.request(b'{"cpu":"PRIVATE_CPU","machineid":"PRIVATE_ID"}',b'Cookie: PRIVATE_COOKIE\r\nX-PRIVATE_HEADER: PRIVATE_VALUE\r\n',b'/tpr/PRIVATE_PATH?deviceid=PRIVATE_QUERY'))
        r=validate_audit(a.finish());s=json.dumps(r)
        self.assertNotIn('PRIVATE_',s);row=r['requests'][0];self.assertTrue(row['credential_header_present']);self.assertEqual(row['unknown_header_count'],1);self.assertEqual(row['query_field_hints'],['device_id'])
    def test_negative_api_not_reconstructed(self):
        a=AuditBuffer(None);self.add(a,self.request(),channel='ctx1',accepted=None);r=a.finish();self.assertEqual(r['requests'],[]);self.assertTrue(r['streams'][0]['api_input_gap'])
    def test_partial_acceptance_only_prefix(self):
        a=AuditBuffer(None);raw=self.request();self.add(a,raw,accepted=12);r=a.finish();self.assertFalse(r['requests'])
    def test_stop_at_gap_not_resync(self):
        a=AuditBuffer(None);raw=self.request();self.add(a,raw,accepted=None);self.add(a,raw,2);r=a.finish();self.assertFalse(r['requests']);self.assertTrue(r['streams'][0]['api_input_gap'])
    def test_truncated_event_not_complete(self):
        a=AuditBuffer(None);self.add(a,self.request(),truncated=True);self.assertFalse(a.finish()['requests'])
    def test_reused_duplicate_sequence_gap(self):
        a=AuditBuffer(None);self.add(a,self.request());self.add(a,self.request());r=a.finish();self.assertTrue(r['streams'][0]['api_input_gap']);self.assertEqual(len(r['requests']),1)
    def test_bad_sequence_sets_limit(self):
        a=AuditBuffer(None);self.add(a,self.request(),seq=None);self.assertTrue(a.finish()['buffer_limit_hit'])
    def test_freeze_erases_references_and_raw(self):
        a=AuditBuffer(b'PRIVATE_CPU');self.add(a,self.request());r=a.finish();self.assertEqual(a.channels,{});self.assertIsNone(a.needle);self.assertIs(r,a.finish())
    def test_layers_separate(self):
        a=AuditBuffer(None);self.add(a,self.request());self.add(a,self.request(),2,channel='ctx1');r=a.finish();self.assertEqual(len(r['requests']),2);self.assertEqual({x['layer'] for x in r['requests']},{'plaintext_winsock_input','pre_tls_sspi_input'})
    def test_only_target_counted(self):
        a=AuditBuffer(None);self.add(a,self.request().replace(b'level3.blizzard.com',b'example.com'));r=a.finish();self.assertEqual(r['summary']['target_requests'],0);self.assertEqual(len(r['requests']),1)
    def test_encoded_cpu_query(self):
        a=AuditBuffer(b'PRIVATE_CPU');self.add(a,self.request(target=b'/tpr/file?x=%50RIVATE_CPU'));self.assertTrue(a.finish()['requests'][0]['cpu_literal_match'])
    def test_incomplete_body_explicit(self):
        a=AuditBuffer(None);raw=self.request(b'12345')[:-2];self.add(a,raw);r=a.finish()['requests'][0];self.assertFalse(r['body_complete']);self.assertEqual(r['body_observed_bytes'],3)
    def test_secret_redaction_default_preserved(self):
        rows,status=parse_requests(self.request(extra=b'Cookie: PRIVATE\r\n'));self.assertIn(['cookie','[REDACTED]'],rows[0]['headers'])
    def test_ambiguous_framing_rejected(self):
        a=AuditBuffer(None);self.add(a,self.request(extra=b'Transfer-Encoding: chunked\r\n'));r=a.finish();self.assertFalse(r['requests']);self.assertEqual(r['streams'][0]['parse_status'],'ambiguous_body_framing')
    def test_chunked(self):
        raw=b'POST /tpr/x HTTP/1.1\r\nHost: level3.blizzard.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n'
        a=AuditBuffer(None);self.add(a,raw);r=a.finish()['requests'][0];self.assertTrue(r['body_complete']);self.assertEqual(r['body_observed_bytes'],3)
    def test_blocked_list_exact(self):
        self.assertEqual(len(BLOCKED),24);self.assertNotIn(TARGET,BLOCKED);self.assertNotIn('www.google.com',BLOCKED)
    def test_sink_accepts_original_bat_zero(self):
        self.assertEqual(classify_addresses(['0.0.0.0','::']),'sink_only');self.assertEqual(classify_addresses(['127.0.0.1','::1']),'sink_only');self.assertNotEqual(classify_addresses(['0.0.0.0','1.1.1.1']),'sink_only')
    def test_profile_needs_all_and_public_target(self):
        p={h:'sink_only' for h in BLOCKED};p[TARGET]='public_only';self.assertTrue(profile_ok(p));p[TARGET]='sink_only';self.assertFalse(profile_ok(p))
    def test_source_no_hosts_mutation_or_process_control(self):
        s=(Path(__file__).resolve().parents[1]/'app/target_monitor.py').read_text()
        for token in ('HostsGuard(','.apply(','.restore(','.spawn(','.kill(','.resume(','.suspend(','Popen('):self.assertNotIn(token,s)
    def test_validator_rejects_extra_raw_field(self):
        a=AuditBuffer(None);self.add(a,self.request());r=a.finish();r['requests'][0]['raw']='PRIVATE'
        with self.assertRaises(ValueError):validate_audit(r)
if __name__=='__main__':unittest.main()
