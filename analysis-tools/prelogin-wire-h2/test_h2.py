import copy
import json
import struct
import unittest
from correlate import analyze,chain,socket_streams,requests
from packets import tcp_runs
from validate import validate,load,LIMITS

REQ=b'POST /data HTTP/1.1\r\nHost: telemetry-in.battle.net\r\nContent-Length: 3\r\n\r\nabc'
CIPHER=b'\x17\x03\x03'+b'SYNTHETIC_CIPHERTEXT_1234567890'
KEY=(b'\x01'*4,12345,b'\x02'*4,443)

def fixtures():
    events=[{'kind':'encrypt','pid':1,'process_sha256':'a'*64,'context':'c1','order':1,'sequence':2,'return_code':0,'complete':True,'before':REQ,'after':CIPHER},
            {'kind':'send','pid':1,'socket':'s1','order':3,'sequence':4,'return_code':len(CIPHER),'complete':True,'accepted_bytes':len(CIPHER),'declared_bytes':len(CIPHER),'asynchronous':False,'ambiguous':False,'raw':CIPHER}]
    return events,{'runs':[{'key':KEY,'chunks':[CIPHER]}]}

def report():
    return dict(schema='bnet-prelogin-wire-h2-1',source_commit='a'*40,run_id='1',status='native_gate_failed_no_installer',error_code='native_gate_failed',selftest=None,bootstrap_pin_match=None,target_launched=False,processes=[],requests=[],parse_states={},network_linked_hardware_requests=0,request_count=0,capture=None,collector_errors=0,dropped_events=0,collector_fatal=False,limits=dict(LIMITS))

def block(kind,body):
    body+=b'\0'*((-len(body))%4);n=len(body)+12
    return struct.pack('<II',kind,n)+body+struct.pack('<I',n)

def pcap(segments):
    out=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
    for seq,payload,frag in segments:
        tcp=struct.pack('!HHIIBBHHH',12345,443,seq,0,0x50,0x18,65535,0,0)+payload
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,frag,64,6,0,KEY[0],KEY[2])
        frame=b'\0'*12+b'\x08\x00'+ip+tcp
        out+=block(6,struct.pack('<5I',0,0,0,len(frame),len(frame))+frame)
    return out

class CorrelationTests(unittest.TestCase):
    def test_all_three_levels(self):
        e,p=fixtures();r=analyze(e,p);self.assertTrue(r['requests'][0]['packet_bytes_linked']);self.assertEqual(r['network_linked_hardware_requests'],0)
    def test_encryption_success_alone_not_send(self):
        e,p=fixtures();r=analyze(e[:1],p);self.assertFalse(r['requests'][0]['socket_send_linked'])
    def test_socket_success_not_wire(self):
        e,p=fixtures();r=analyze(e,{'runs':[]});self.assertTrue(r['requests'][0]['socket_send_linked']);self.assertFalse(r['requests'][0]['packet_bytes_linked'])
    def test_negative_return_cannot_be_forged_as_accepted(self):
        e,p=fixtures();e[1]['return_code']=-1;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_duplicate_packet_flow_is_ambiguous(self):
        e,p=fixtures();p['runs'].append({'key':(KEY[0],12346,KEY[2],443),'chunks':[CIPHER]});r=analyze(e,p)['requests'][0];self.assertTrue(r['socket_send_linked']);self.assertFalse(r['packet_bytes_linked'])
    def test_partial_write_does_not_count_full_cipher(self):
        e,p=fixtures();e[1]['accepted_bytes']=4;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_split_writes_reassemble(self):
        e,p=fixtures();s=e.pop();a=dict(s,raw=CIPHER[:9],accepted_bytes=9);b=dict(s,order=5,raw=CIPHER[9:],accepted_bytes=len(CIPHER)-9);self.assertTrue(analyze(e+[a,b],p)['requests'][0]['packet_bytes_linked'])
    def test_async_pending_is_not_success(self):
        e,p=fixtures();e[1]['asynchronous']=True;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_failed_send_is_not_success(self):
        e,p=fixtures();e[1]['accepted_bytes']=None;e[1]['return_code']=-1;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_concurrent_socket_rejected(self):
        e,p=fixtures();e[1]['ambiguous']=True;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_ambiguous_duplicate_cipher_rejected(self):
        e,p=fixtures();e.append(dict(e[1],socket='s2'));self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_failed_encryption_not_request(self):
        e,p=fixtures();e[0]['return_code']=-1;self.assertEqual(analyze(e,p)['requests'],[])
    def test_wrong_pid_not_linked(self):
        e,p=fixtures();e[1]['pid']=2;self.assertFalse(analyze(e,p)['requests'][0]['socket_send_linked'])
    def test_unknown_destination_redacted(self):
        e,p=fixtures();e[0]['before']=REQ.replace(b'telemetry-in.battle.net',b'private.invalid');self.assertEqual(analyze(e,p)['requests'][0]['destination'],'other')
    def test_requests_never_resync_inside_body(self):
        r,status=requests(b'x'+REQ);self.assertEqual(r,[])
    def test_reject_duplicate_framing(self):
        r,status=requests(REQ.replace(b'Content-Length: 3',b'Content-Length: 3\r\nContent-Length: 3'));self.assertEqual(r,[])
    def test_response_requires_reverse_wire_and_same_socket(self):
        e,p=fixtures();cipher=b'ENCRYPTED_REPLY_1234567890123456789';reverse=(KEY[2],KEY[3],KEY[0],KEY[1])
        e += [dict(kind='recv',pid=1,socket='s1',order=5,sequence=6,return_code=len(cipher),complete=True,accepted_bytes=len(cipher),asynchronous=False,ambiguous=False,raw=cipher),dict(kind='decrypt',pid=1,context='c1',order=7,sequence=8,return_code=0,complete=True,before=cipher,after=b'HTTP/1.1 200 OK\r\n\r\n')]
        self.assertIsNone(analyze(e,p)['requests'][0]['http_response_status'])
        p['runs'].append(dict(key=reverse,chunks=[cipher]));self.assertEqual(analyze(e,p)['requests'][0]['http_response_status'],200)
        e[-2]['socket']='s2';self.assertIsNone(analyze(e,p)['requests'][0]['http_response_status'])
    def test_inputs_unchanged(self):
        e,p=fixtures();a,b=copy.deepcopy(e),copy.deepcopy(p);analyze(e,p);self.assertEqual((e,p),(a,b))

class PacketTests(unittest.TestCase):
    def test_reorder_retransmit(self):
        p=tcp_runs(pcap([(110,CIPHER[10:],0),(100,CIPHER[:10],0),(100,CIPHER[:10],0)]));self.assertEqual(p['runs'][0]['chunks'],[CIPHER])
    def test_gap_never_filled(self):
        p=tcp_runs(pcap([(100,CIPHER[:10],0),(111,CIPHER[10:],0)]));self.assertEqual(len(p['runs'][0]['chunks']),2)
    def test_conflicting_overlap_rejected(self):
        p=tcp_runs(pcap([(100,CIPHER,0),(100,b'BAD',0)]));self.assertEqual(p['runs'],[]);self.assertEqual(p['issues']['tcp_overlap_conflict'],1)
    def test_fragment_explicitly_unsupported(self):
        p=tcp_runs(pcap([(100,CIPHER,0x2000)]));self.assertEqual(p['runs'],[]);self.assertEqual(p['issues']['ip_fragments_unsupported'],1)
    def test_bad_block_refused(self):
        with self.assertRaises(ValueError):tcp_runs(pcap([(100,CIPHER,0)])[:-1])
    def test_tcp_sequence_wrap(self):
        p=tcp_runs(pcap([(0xfffffff8,CIPHER[:8],0),(0,CIPHER[8:],0)]));self.assertEqual(p['runs'][0]['chunks'],[CIPHER])

class SanitizerTests(unittest.TestCase):
    def test_minimal_failure_report(self):validate(report())
    def test_raw_body_rejected(self):
        r=report();r['body']='private'
        with self.assertRaises(ValueError):validate(r)
    def test_fake_hardware_verdict_rejected(self):
        r=report();r['network_linked_hardware_requests']=1
        with self.assertRaises(ValueError):validate(r)
    def test_duplicate_json_key_rejected(self):
        raw=json.dumps(report()).replace('"run_id": "1"','"run_id": "1", "run_id": "2"')
        with self.assertRaises(ValueError):load(raw)
    def test_ungated_launch_rejected(self):
        r=report();r['target_launched']=True
        with self.assertRaises(ValueError):validate(r)
    def test_storage_claim_rejected(self):
        r=report();r['limits']['server_storage_proven']=True
        with self.assertRaises(ValueError):validate(r)

if __name__=='__main__':unittest.main()
