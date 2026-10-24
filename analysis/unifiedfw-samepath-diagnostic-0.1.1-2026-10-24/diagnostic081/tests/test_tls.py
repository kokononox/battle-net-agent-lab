from pathlib import Path
import http.server,json,os,socket,ssl,subprocess,sys,tempfile,threading,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'diagnostic081'))
import https_common as h
URL='https://ufw-test.example/probe.php';IP='9.9.9.9'
def token(role='A'):return dict(kind='unifiedfw-traffic-1',nonce='a'*64,request_id='b'*32,role=role)
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
