import unittest,json
from origin_audit import OriginAudit
K='0123456789abcdef0123456789abcdef';P='/tpr/fixture/data/01/23/'+K
B=('GET '+P+' HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n').encode()
class OriginTests(unittest.TestCase):
 def test_prior_literal_and_no_raw_export(self):
  a=OriginAudit();a.source(1,b'prefix'+K.encode(),'disk_ReadFile_sync');a.requests(2,B,[{'module':'Agent','relative_offset':'0x1'}]);r=a.report();self.assertTrue(r['targets'][0]['occurrences'][0]['preceded_request_observation']);self.assertNotIn(K,json.dumps(r));self.assertFalse(r['targets'][0]['derivation_proven'])
 def test_binary(self):
  a=OriginAudit();a.source(1,bytes.fromhex(K),'disk_ReadFile_sync');a.requests(2,B);self.assertIn('binary_16_bytes',a.rows[0]['occurrences'][0]['representation'])
 def test_known_path_excluded(self):
  a=OriginAudit([P]);a.requests(1,B);self.assertEqual(a.rows,[])
 def test_split_receive(self):
  a=OriginAudit();a.source(1,K[:13].encode(),'selected_two_host_recv');a.source(1,K[13:].encode(),'selected_two_host_recv');a.requests(2,B);self.assertEqual(len(a.rows[0]['occurrences']),1)
 def test_different_streams_not_joined(self):
  a=OriginAudit();a.source(1,K[:13].encode(),'selected_two_host_recv');a.source(2,K[13:].encode(),'selected_two_host_recv');a.requests(3,B);self.assertEqual(a.rows[0]['occurrences'],[])
 def test_noncontiguous_file_not_joined(self):
  a=OriginAudit();a.source(1,K[:13].encode(),'disk_ReadFile_sync');a.source(1,K[13:].encode(),'disk_ReadFile_sync');a.requests(2,B);self.assertEqual(a.rows[0]['occurrences'],[])
 def test_later_occurrence_not_prior(self):
  a=OriginAudit();a.requests(2,B);a.source(1,K.encode(),'disk_ReadFile_sync');self.assertFalse(a.rows[0]['occurrences'][0]['preceded_request_observation'])
 def test_retention_eviction(self):
  a=OriginAudit(limit=40);a.source(1,K.encode(),'disk_ReadFile_sync');a.source(2,b'x'*40,'disk_ReadFile_sync');a.requests(3,B);self.assertEqual(a.rows[0]['occurrences'],[]);self.assertEqual(a.counts['evicted_chunks'],1)
 def test_fragmented_requests(self):
  a=OriginAudit();a.requests(1,B[:20]);a.requests(1,B[20:]);self.assertEqual(len(a.rows),1)
 def test_query_and_bad_fanout_rejected(self):
  a=OriginAudit();a.requests(1,B.replace(K.encode()+b' HTTP',K.encode()+b'?x=1 HTTP'));a.requests(2,B.replace(b'/01/23/',b'/ff/23/'));self.assertEqual(a.rows,[])
 def test_close_does_not_join_reused_socket(self):
  a=OriginAudit();a.source(1,K[:13].encode(),'selected_two_host_recv');a.close(1);a.source(1,K[13:].encode(),'selected_two_host_recv');a.requests(2,B);self.assertEqual(a.rows[0]['occurrences'],[])
 def test_utf16(self):
  a=OriginAudit();a.source(1,K.encode('utf-16le'),'disk_ReadFile_sync');a.requests(2,B);self.assertIn('UTF16LE_lower_hex',a.rows[0]['occurrences'][0]['representation'])
