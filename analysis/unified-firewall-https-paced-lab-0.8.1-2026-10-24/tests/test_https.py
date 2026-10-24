from pathlib import Path
import copy,datetime,re,http.server,importlib.util,io,json,os,socket,ssl,subprocess,sys,tempfile,threading,time,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'lab'),str(ROOT/'app')]
import https_common as h
from coexistence import build_coexistence_request,classify_coexistence
from test_coexistence import report as tcp_report
from traffic_common import challenge
URL='https://ufw-test.example/probe.php';IP='9.9.9.9'
def token(role='A'):return dict(kind='unifiedfw-traffic-1',nonce='a'*64,request_id='b'*32,role=role)
def https_report():
    r=tcp_report();r.update(transport='https_php',endpoint=dict(https_url=URL,address=IP,port=443))
    for p in r['phases']:
        for stage in ('during','after_restore'):
            for row in p[stage]:row.update(transport='https_php',tls_verified=row['handshake_ok'],http_status=200 if row['handshake_ok'] else None)
    return r
class MemorySocket:
    def __init__(self,data):self.data=data
    def makefile(self,mode):return io.BytesIO(self.data)
    def settimeout(self,value):pass

def http_message(value=None,headers=None,status='200 OK'):
    body=json.dumps(value or dict(token(),observed_peer='127.0.0.1')).encode()
    head={'Content-Type':'application/json','Content-Length':str(len(body))}
    if headers:head.update(headers)
    return ('HTTP/1.1 '+status+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in head.items())+'\r\n').encode()+body

class HTTPSDataTests(unittest.TestCase):
    def test_canonical_url_and_fixed_443(self):self.assertEqual(h.https_endpoint(URL,IP),dict(url=URL,host='ufw-test.example',path='/probe.php',address=IP,port=443,transport='https_php'))
    def test_unsafe_urls_rejected(self):
        for u in ['http://ufw-test.example/probe.php','https://user:pass@ufw-test.example/probe.php',URL+'?a=1',URL+'#x','https://ufw-test.example:443/probe.php','https://ufw-test.example:4443/probe.php','https://9.9.9.9/probe.php','https://localhost/probe.php','https://ufw-test.example/../probe.php','https://ufw-test.example/a%2fprobe.php','https://ufw-test.example/probe.php\r\nX: bad','https://ufw-test.example/index.html','https://ufw-test.example/'+('a'*600)+'.php']:
            with self.subTest(u=u),self.assertRaises(ValueError):h.https_endpoint(u,IP)
    def test_private_loopback_and_reserved_IPs_rejected(self):
        for ip in ['127.0.0.1','10.0.0.1','192.168.1.1','::1','203.0.113.1','224.0.0.1']:
            with self.assertRaises(ValueError):h.https_endpoint(URL,ip)
    def test_dns_must_include_selected_ip_without_replacing_it(self):
        cfg=h.https_endpoint(URL,IP)
        with patch.object(h.socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(IP,443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]):self.assertEqual(h.verify_dns(cfg),['8.8.8.8',IP]);self.assertEqual(cfg['address'],IP)
        with patch.object(h.socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]),self.assertRaisesRegex(ValueError,'selected_IP_not'):h.verify_dns(cfg)
    def test_https_compiles_only_exact_443_without_weakening_old_port_gate(self):
        q=build_coexistence_request(IP,443,root=Path('C:/Fixture'),inspector=lambda p:'a'*64,https_url=URL)
        self.assertEqual(q['https_host'],'ufw-test.example')
        self.assertTrue(all(r['spec']['port']==443 and r['spec']['remote_addresses']==[IP+'/32'] for p in q['phases'] for r in p['request']['plan']['rules']))
        with self.assertRaises(ValueError):build_coexistence_request(IP,443,root=Path('C:/Fixture'))
        with self.assertRaises(ValueError):build_coexistence_request(IP,4443,https_url=URL)
    def test_HTTP_validates_exact_challenge_and_server_peer(self):self.assertEqual(h.read_response(MemorySocket(http_message()),time.monotonic()+2,token()),'127.0.0.1')
    def test_redirect_html_compression_oversize_and_wrong_nonce_rejected(self):
        for payload in [http_message(status='302 Found'),http_message(headers={'Content-Type':'text/html'}),http_message(headers={'Content-Encoding':'gzip'}),http_message(headers={'Content-Length':'99999'}),http_message(dict(token(),nonce='c'*64,observed_peer='127.0.0.1')),http_message(dict(token(),observed_peer='not-an-ip')),http_message(dict(token(),observed_peer='127.0.0.1',extra='bad'))]:
            with self.assertRaises((ValueError,OSError)):h.read_response(MemorySocket(payload),time.monotonic()+2,token())
    def test_chunked_is_bounded_and_supported(self):
        b=json.dumps(dict(token(),observed_peer='::1')).encode();raw=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'+f'{len(b):x}\r\n'.encode()+b+b'\r\n0\r\n\r\n'
        self.assertEqual(h.read_response(MemorySocket(raw),time.monotonic()+2,token()),'::1')
        with self.assertRaises(ValueError):h.read_response(MemorySocket(raw.replace(b'Transfer-Encoding:',b'Content-Length: 1\r\nTransfer-Encoding:')),time.monotonic()+2,token())
    def test_header_budget_duplicates_and_truncated_body_rejected(self):
        for raw in [http_message().replace(b'Content-Type:',b'Content-Length: 1\r\nContent-Type:'),b'HTTP/1.1 200 OK\r\nX: '+b'a'*40000+b'\r\n\r\n',http_message()[:-4]]:
            with self.assertRaises((ValueError,OSError)):h.read_response(MemorySocket(raw),time.monotonic()+2,token())
    def test_https_classification_retains_narrow_claims(self):
        r=classify_coexistence(https_report());self.assertEqual(r['outcome'],'passed');self.assertTrue(r['https_challenge_verified']);self.assertFalse(r['global_whitelist_tested']);self.assertFalse(r['no_leak_certified'])
    def test_missing_TLS_verification_never_passes(self):
        for k,v in [('tls_verified',False),('http_status',302),('transport','tcp')]:
            r=https_report();r['phases'][0]['during'][0][k]=v;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
    def test_bad_tls_after_a_blocked_tcp_connection_is_failure_not_block_success(self):
        r=https_report();row=next(x for x in r['phases'][2]['during'] if x['role']=='A');row.update(connected=True,tls_verified=False,http_status=None,handshake_ok=False)
        self.assertEqual(classify_coexistence(r)['outcome'],'failed')
    def test_socket_resource_failure_not_counted_as_block(self):
        from traffic_common import probe
        with patch.object(h.socket,'socket',side_effect=OSError(24,'mock file descriptor exhaustion')):
            self.assertFalse(h.probe_https(URL,IP,token())['probe_valid'])
            self.assertFalse(probe(IP,39443,token())['probe_valid'])
    def test_a_real_connection_attempt_timeout_stays_distinct_from_execution_failure(self):
        class TimeoutSocket:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def settimeout(self,*args):pass
            def connect(self,*args):raise TimeoutError('mock connect timeout')
        with patch.object(h.socket,'socket',return_value=TimeoutSocket()):
            r=h.probe_https(URL,IP,token());self.assertTrue(r['connection_attempted']);self.assertTrue(r['probe_valid']);self.assertFalse(r['connected'])
    def test_validation_disabled_context_is_refused_before_connect(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        with patch.object(h.ssl,'create_default_context',return_value=context),patch.object(h.socket,'socket') as network:
            result=h.probe_https(URL,IP,token());self.assertFalse(result['probe_valid']);network.assert_not_called()
    def test_PHP_source_has_bounded_input_expiry_and_no_command_or_file_write_path(self):
        folder=ROOT/'server/php';deployment=json.loads((folder/'DEPLOYMENT.json').read_text());source=(folder/deployment['filename']).read_text()
        self.assertTrue(source.startswith('<?php'));self.assertIn(deployment['expires_utc'],source);self.assertIn("file_get_contents('php://input', false, null, 0, 1025)",source)
        self.assertIsNone(re.search(r'\b(?:eval|system|shell_exec|exec|passthru|file_put_contents|fopen|include|require)\s*\(',source))
        self.assertIn("header('Cache-Control: no-store, max-age=0')",source)
    def test_tls_context_preparation_error_is_not_network_block_evidence(self):
        with patch.object(h.ssl,'create_default_context',side_effect=OSError('mock missing CA store')):
            r=h.probe_https(URL,IP,token());self.assertFalse(r['probe_valid']);self.assertFalse(r['connected'])

class ProbePathTests(unittest.TestCase):
    def exercise(self,filename,jobname,https=False):
        spec=importlib.util.spec_from_file_location('isolated_probe',ROOT/'lab'/filename);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);job=root/'private-state'/jobname/'id';job.mkdir(parents=True);req=job/'request.json';out=job/'result.json'
            q=dict(address=IP,port=443 if https else 39443,challenge=token())
            if https:q['https_url']=URL
            req.write_text(json.dumps(q));m.__file__=str(root/'lab'/filename)
            method='probe_https' if https else 'probe'
            with patch.object(m,method,return_value=dict(mock_only=True)) as mock,patch.object(sys,'argv',[filename,'--request',str(req),'--output',str(out)]):
                if jobname in (('coexistence-jobs',) if https else ('traffic-jobs','coexistence-jobs')):
                    self.assertEqual(m.main(),0);mock.assert_called_once();self.assertTrue(json.loads(out.read_text())['mock_only'])
                else:
                    with self.assertRaises(ValueError):m.main()
                    mock.assert_not_called()
    def test_TCP_child_accepts_coexistence_job_regression(self):self.exercise('traffic-probe.py','coexistence-jobs')
    def test_TCP_child_still_accepts_traffic_jobs(self):self.exercise('traffic-probe.py','traffic-jobs')
    def test_TCP_child_rejects_unrelated_job_tree(self):self.exercise('traffic-probe.py','lab-jobs')
    def test_HTTPS_child_accepts_only_coexistence_tree(self):
        self.exercise('https-probe.py','coexistence-jobs',True);self.exercise('https-probe.py','traffic-jobs',True)

class HTTPSLocalTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        def openssl(args):subprocess.run(['openssl',*args],cwd=cls.root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-subj','/CN=UnifiedFW Local Test CA','-days','1','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
        openssl(['req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=ufw-test.example'])
        (cls.root/'extensions.txt').write_text('subjectAltName=DNS:ufw-test.example\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        openssl(['x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','extensions.txt'])
        cls.original_socket=socket.socket;cls.original_context=ssl.create_default_context
        cls.requests=[];cls.sni=[];cls.mode='good'
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                q=json.loads(self.rfile.read(int(self.headers['Content-Length'])));cls.requests.append((self.path,self.headers['Host']))
                if cls.mode=='wrong_nonce':q['nonce']='c'*64
                b=json.dumps(dict(q,observed_peer='127.0.0.1')).encode();self.send_response(302 if cls.mode=='redirect' else 200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
            def log_message(self,*args):pass
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cls.root/'server.pem',cls.root/'server.key');context.set_servername_callback(lambda sock,name,ctx:cls.sni.append(name))
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.temp.cleanup()
    def attempt(self,mode='good',trusted=True,url=URL):
        self.__class__.mode=mode;dialed=[];port=self.server.server_address[1];base=self.original_socket
        class LocalDial(base):
            def connect(self,destination):dialed.append(destination);return super().connect(('127.0.0.1',port))
        def context():return self.__class__.original_context(cafile=str(self.root/'ca.pem') if trusted else None)
        with patch.object(h.socket,'socket',LocalDial),patch.object(h.ssl,'create_default_context',side_effect=context),patch.object(h.socket,'getaddrinfo',side_effect=AssertionError('production probe must not resolve DNS')),patch.dict(os.environ,{'HTTPS_PROXY':'http://127.0.0.1:1','HTTP_PROXY':'http://127.0.0.1:1'}):r=h.probe_https(url,IP,token())
        self.assertEqual(dialed,[(IP,443)]);return r
    def test_real_TLS_valid_hostname_SNI_Host_and_echo(self):
        r=self.attempt();self.assertTrue(r['handshake_ok']);self.assertTrue(r['tls_verified']);self.assertEqual(r['http_status'],200);self.assertEqual(self.sni[-1],'ufw-test.example');self.assertEqual(self.requests[-1],('/probe.php','ufw-test.example'))
    def test_untrusted_CA_is_rejected_after_TCP_connect(self):
        r=self.attempt(trusted=False);self.assertTrue(r['connected']);self.assertFalse(r['tls_verified']);self.assertFalse(r['handshake_ok'])
    def test_wrong_certificate_hostname_rejected(self):
        r=self.attempt(url='https://wrong-test.example/probe.php');self.assertTrue(r['connected']);self.assertFalse(r['tls_verified']);self.assertFalse(r['handshake_ok'])
    def test_redirect_not_followed(self):
        before=len(self.requests);r=self.attempt(mode='redirect');self.assertTrue(r['tls_verified']);self.assertFalse(r['handshake_ok']);self.assertEqual(len(self.requests),before+1)
    def test_wrong_echo_not_accepted(self):
        r=self.attempt(mode='wrong_nonce');self.assertTrue(r['connected']);self.assertFalse(r['handshake_ok'])
if __name__=='__main__':unittest.main()
