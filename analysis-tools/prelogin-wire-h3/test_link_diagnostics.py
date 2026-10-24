import copy
import unittest
from correlate import analyze,base
REQ=b'POST /data HTTP/1.1\r\nHost: telemetry-in.battle.net\r\nContent-Length: 3\r\n\r\nabc'
CIPHER=b'\x17\x03\x03'+bytes(range(100))
KEY=(b'\x01'*4,12345,b'\x02'*4,443)
def fixture():
    return [dict(kind='encrypt',pid=1,process_sha256='a'*64,context='c1',order=1,sequence=2,return_code=0,complete=True,before=REQ,after=CIPHER),dict(kind='send',pid=1,socket='s1',order=3,sequence=4,return_code=len(CIPHER),complete=True,accepted_bytes=len(CIPHER),asynchronous=False,ambiguous=False,raw=CIPHER)],{'runs':[dict(key=KEY,chunks=[CIPHER])]}
class Diagnostics(unittest.TestCase):
    def review(self,e,p):
        before=copy.deepcopy((e,p));expected=base.analyze(e,p);actual=analyze(e,p)
        d=actual.pop('link_diagnostics');self.assertEqual(actual,expected);self.assertEqual((e,p),before)
        return actual,d
    def test_full_match(self):
        e,p=fixture();r,d=self.review(e,p);self.assertTrue(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_matches'],1)
    def test_no_wire(self):
        e,p=fixture();p['runs']=[];r,d=self.review(e,p);self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_matches'],0)
    def test_prefix_does_not_promote(self):
        e,p=fixture();p['runs'][0]['chunks']=[CIPHER[:40]];r,d=self.review(e,p);self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_prefix_matches'],1);self.assertEqual(d[0][0]['packet_suffix_matches'],0)
    def test_suffix_does_not_promote(self):
        e,p=fixture();p['runs'][0]['chunks']=[CIPHER[-40:]];r,d=self.review(e,p);self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_suffix_matches'],1)
    def test_gap_does_not_promote(self):
        e,p=fixture();p['runs'][0]['chunks']=[CIPHER[:40],CIPHER[-40:]];r,d=self.review(e,p);self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_prefix_matches'],1);self.assertEqual(d[0][0]['packet_suffix_matches'],1)
    def test_duplicate_flow_does_not_promote(self):
        e,p=fixture();p['runs'].append(dict(key=(KEY[0],23456,KEY[2],443),chunks=[CIPHER]));r,d=self.review(e,p);self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['packet_matches'],2)
    def test_wrong_process(self):
        e,p=fixture();e[1]['pid']=2;r,d=self.review(e,p);self.assertFalse(r['requests'][0]['socket_send_linked']);self.assertFalse(d[0][0]['socket_pid_match'])
    def test_failed_context_no_diagnostics(self):
        e,p=fixture();e[0]['return_code']=-1;r,d=self.review(e,p);self.assertEqual(d,[])
    def test_multiple_requests_alignment(self):
        e,p=fixture();e[0]['before']=REQ+REQ;r,d=self.review(e,p);self.assertEqual(len(d),2)
    def test_raw_container_not_valid_network_evidence(self):
        e,p=fixture();p['runs']=[];p['_private_pcap_bytes']=b'CONTAINER'+CIPHER+b'OTHER';r,d=self.review(e,p)
        self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual([d[0][0][k] for k in ('pcap_prefix_matches','pcap_middle_matches','pcap_suffix_matches')],[1,1,1])
    def test_raw_scan_explicitly_unavailable(self):
        e,p=fixture();r,d=self.review(e,p);self.assertIsNone(d[0][0]['pcap_prefix_matches'])
    def test_raw_scan_available_but_no_match(self):
        e,p=fixture();p['_private_pcap_bytes']=b'UNRELATED';r,d=self.review(e,p);self.assertEqual(d[0][0]['pcap_prefix_matches'],0)
    def test_raw_scan_counter_capped(self):
        e,p=fixture();p['_private_pcap_bytes']=CIPHER*5;r,d=self.review(e,p);self.assertEqual(d[0][0]['pcap_prefix_matches'],2)
    def test_rejected_ip_not_network_evidence(self):
        e,p=fixture();p['runs']=[];p['_private_rejected_ip_frames']=[CIPHER];r,d=self.review(e,p)
        self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['rejected_ip_prefix_matches'],1)
    def test_conflicted_segments_not_network_evidence(self):
        e,p=fixture();p['runs']=[];p['_private_conflicted_segments']=[CIPHER];r,d=self.review(e,p)
        self.assertFalse(r['requests'][0]['packet_bytes_linked']);self.assertEqual(d[0][0]['conflicted_segment_prefix_matches'],1)
    def test_private_bytes_not_exported(self):
        e,p=fixture();r,d=self.review(e,p);self.assertEqual(set(d[0][0]),{'socket_matches','socket_pid_match','packet_matches','packet_prefix_matches','packet_suffix_matches','plaintext_bytes','encrypted_bytes','pcap_prefix_matches','pcap_middle_matches','pcap_suffix_matches','rejected_ip_prefix_matches','rejected_ip_middle_matches','rejected_ip_suffix_matches','valid_segment_prefix_matches','valid_segment_middle_matches','valid_segment_suffix_matches','conflicted_segment_prefix_matches','conflicted_segment_middle_matches','conflicted_segment_suffix_matches'})
if __name__=='__main__':unittest.main()
