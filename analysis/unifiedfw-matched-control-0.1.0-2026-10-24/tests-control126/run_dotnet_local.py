"""Actual Linux .NET TLS; test-only loopback gate; no system trust changes."""
from pathlib import Path
import http.server,json,os,shutil,ssl,subprocess,sys,threading,uuid
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests-control126'))
from test_tls import HTTPSLocalTLSTests as Fixture

def main():
 Fixture.setUpClass();server=None;thread=None
 script=ROOT/'control126/.test-reference.ps1';job=ROOT/'private-state/control126-jobs'/('test-'+uuid.uuid4().hex);job.mkdir(parents=True)
 try:
  server=http.server.ThreadingHTTPServer(('127.0.0.1',443),Fixture.server.RequestHandlerClass)
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(Fixture.root/'server.pem',Fixture.root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  source=(ROOT/'tests-control126/reference-fixture.ps1').read_text('utf-8-sig').replace('function TAssertPublicIPv4([string]$Text){',"function TAssertPublicIPv4([string]$Text){\n if($Text -ceq '127.0.0.1'){return} # test-only admission for local server")
  script.write_text(source,encoding='utf-8-sig');(Fixture.root/'empty-cas').mkdir();cases=[]
  for name,trusted,host,mode in [('valid',True,'ufw-test.example','good'),('wrong_hostname',True,'wrong-test.example','good'),('untrusted_CA',False,'ufw-test.example','good'),('redirect',True,'ufw-test.example','redirect'),('wrong_echo',True,'ufw-test.example','wrong_nonce')]:
   Fixture.mode=mode;req=job/(name+'-request.json');out=job/(name+'-output.json')
   req.write_text(json.dumps({'url':'https://'+host+'/probe.php','address':'127.0.0.1','challenge':dict(kind='unifiedfw-traffic-1',nonce='a'*64,request_id='b'*32,role='REF')}))
   env=os.environ.copy();env.pop('SSL_CERT_FILE',None);env.pop('SSL_CERT_DIR',None)
   if trusted:env.update(SSL_CERT_FILE=str(Fixture.root/'ca.pem'),SSL_CERT_DIR=str(Fixture.root/'empty-cas'))
   cp=subprocess.run(['/data/devtools/pwsh/pwsh','-NoLogo','-NoProfile','-File',str(script),'-Request',str(req),'-Output',str(out)],env=env,capture_output=True,text=True,timeout=20)
   assert cp.returncode==0,(name,cp.stderr)
   row=json.loads(out.read_text('utf-8-sig'));assert row['connected'] is True,(name,row)
   if name=='valid':assert row['handshake_ok'] is True and row['stage']=='complete',(name,row)
   else:assert row['handshake_ok'] is False,(name,row)
   if name in ('wrong_hostname','untrusted_CA'):assert row['tls_verified'] is False and row['stage']=='tls_handshake',(name,row)
   if name in ('redirect','wrong_echo'):assert row['tls_verified'] is True and row['stage']=='http_response_and_echo',(name,row)
   cases.append({k:row.get(k) for k in ('connected','tls_verified','handshake_ok','stage')}|{'case':name})
  report=dict(passed=True,cases=cases,environment='Linux PowerShell 7 .NET; real loopback TLS',Windows_tested=False,user_endpoint_contacted=False,system_trust_store_changed=False,certificate_accept_all_callback=False,temporary_CA_via_child_environment=True,public_IP_gate_substituted_for_loopback_in_temporary_test_script_only=True)
  (ROOT/'evidence-control126').mkdir(exist_ok=True);(ROOT/'evidence-control126/dotnet-local.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
 finally:
  if script.exists():script.unlink()
  shutil.rmtree(job,ignore_errors=True)
  if server:server.shutdown();server.server_close()
  if thread:thread.join()
  Fixture.tearDownClass()
if __name__=='__main__':main()
