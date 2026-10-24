from pathlib import Path
import copy,ipaddress,json,socket,subprocess,sys,tempfile,threading,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lab'));sys.path.insert(0,str(ROOT/'app'))
from traffic_common import classify,endpoint,probe,challenge,KIND
from traffic import build_request

def matrix():
    result=dict(phases=[]);counter=0
    for name,blocked in (('baseline',set()),('only_A',{'A'}),('only_B',{'B'}),('both',{'A','B'})):
        p=dict(name=name,restored=True,baseline_strict_equal=True,during=[],after_restore=[])
        for stage in ('during','after_restore'):
            for role in ('A','B','REF'):
                for round in range(3):
                    counter+=1;ok=not(stage=='during' and role in blocked)
                    p[stage].append(dict(role=role,round=round,connected=ok,handshake_ok=ok,probe_valid=True,request_id=f'{counter:032x}'))
        result['phases'].append(p)
    return result
class TrafficTests(unittest.TestCase):
    def test_good_matrix_is_only_narrow_pass(self):
        r=classify(matrix());self.assertEqual(r['outcome'],'passed');self.assertFalse(r['whitelist_tested']);self.assertFalse(r['no_leak_certified']);self.assertFalse(r['packet_capture_performed'])
    def test_every_blocked_socket_success_is_failure_even_without_handshake(self):
        for i,role in ((1,'A'),(2,'B'),(3,'A'),(3,'B')):
            m=matrix();r=next(r for r in m['phases'][i]['during'] if r['role']==role);r.update(connected=True,handshake_ok=False)
            self.assertEqual(classify(m)['outcome'],'failed')
    def test_unreachable_server_is_never_passed(self):
        m=matrix()
        for p in m['phases']:
            for rows in (p['during'],p['after_restore']):
                for r in rows:r.update(connected=False,handshake_ok=False)
        self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_reference_failure_invalidates_both_blocked_phase(self):
        m=matrix();next(r for r in m['phases'][3]['during'] if r['role']=='REF').update(connected=False,handshake_ok=False)
        self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_failed_child_process_not_counted_as_block(self):
        m=matrix();m['phases'][1]['during'][0]['probe_valid']=False;self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_restore_drift_is_not_passed(self):
        m=matrix();m['phases'][2]['baseline_strict_equal']=False;self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_no_recovery_of_connection_is_not_passed(self):
        m=matrix();m['phases'][1]['after_restore'][0].update(connected=False,handshake_ok=False);self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_partial_phases_rejected(self):
        m=matrix();m['phases'].pop();self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_duplicate_rounds_rejected(self):
        m=matrix();m['phases'][0]['during'][0]['round']=1;self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_request_replay_rejected(self):
        m=matrix();m['phases'][1]['during'][0]['request_id']=m['phases'][0]['during'][0]['request_id'];self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_contradictory_flags_rejected(self):
        m=matrix();m['phases'][1]['during'][0].update(connected=False,handshake_ok=True);self.assertEqual(classify(m)['outcome'],'inconclusive')
    def test_only_public_unicast_literal_and_high_port(self):
        self.assertEqual(endpoint('8.8.8.8',39443),('8.8.8.8',39443))
        for host,port in [('example.com',39443),('127.0.0.1',39443),('10.0.0.1',39443),('224.0.0.1',39443),('::1',39443),('8.8.8.8',443),('8.8.8.8',True),('8.8.8.8',65536)]:
            with self.assertRaises(ValueError):endpoint(host,port)
    def test_plans_are_fixed_exact_endpoint_and_bundled_images(self):
        q=build_request('8.8.8.8',39443,root=Path(r'C:\Fixture'),inspector=lambda p:'a'*64)
        self.assertEqual([len(p['request']['plan']['rules']) for p in q['phases']],[1,1,2])
        for phase in q['phases']:
            self.assertEqual(phase['request']['mode'],'blacklist_only')
            for r in phase['request']['plan']['rules']:
                self.assertEqual(r['component'],'blacklist');self.assertEqual(r['spec']['remote_addresses'],['8.8.8.8/32']);self.assertEqual(r['spec']['port'],39443)
                self.assertIn(r['spec']['program'],[p['path'] for p in q['programs']]);self.assertEqual(r['spec']['interface_type'],'Any')
    def test_challenge_rejects_unbounded_or_unknown_fields(self):
        good=dict(kind=KIND,nonce='a'*64,request_id='b'*32,role='A');self.assertEqual(challenge(good),good)
        for bad in (dict(good,extra='bad'),dict(good,nonce='a'*5000),dict(good,role='other')):
            with self.assertRaises(ValueError):challenge(bad)
    def test_real_echo_server_local_integration_not_firewall(self):
        # Only this integration test bypasses the public-IP gate for sandbox localhost.
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        server=subprocess.Popen([sys.executable,str(ROOT/'server/echo-server.py'),'--bind','127.0.0.1','--port',str(port),'--seconds','30','--max-connections','1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        ready=[];thread=threading.Thread(target=lambda:ready.append(server.stdout.readline()),daemon=True);thread.start();thread.join(4)
        try:
            self.assertTrue(ready, 'server did not start');self.assertEqual(json.loads(ready[0])['port'],port)
            request=dict(kind=KIND,nonce='a'*64,request_id='b'*32,role='A')
            with patch('traffic_common.endpoint',return_value=('127.0.0.1',port)):r=probe('127.0.0.1',port,request)
            self.assertTrue(r['connected']);self.assertTrue(r['handshake_ok']);self.assertEqual(r['server_observed_peer'],'127.0.0.1')
            server.wait(timeout=4)
        finally:
            if server.poll() is None:server.kill();server.wait()
            server.stdout.close();server.stderr.close()
    def test_rejected_challenge_cannot_be_success(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1]
            def wrong():
                with listener.accept()[0] as conn:
                    conn.recv(2048);conn.sendall(b'{"kind":"wrong"}\n')
            t=threading.Thread(target=wrong,daemon=True);t.start()
            with patch('traffic_common.endpoint',return_value=('127.0.0.1',port)):r=probe('127.0.0.1',port,dict(kind=KIND,nonce='a'*64,request_id='b'*32,role='A'))
            t.join(3);self.assertTrue(r['connected']);self.assertFalse(r['handshake_ok'])
if __name__=='__main__':unittest.main()
