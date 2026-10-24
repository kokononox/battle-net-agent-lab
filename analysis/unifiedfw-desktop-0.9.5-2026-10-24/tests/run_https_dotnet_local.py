"""Linux-only localhost TLS integration; temporary private CA via child environment.
No production certificate callback or system trust-store changes are used.
"""
from pathlib import Path
import http.server,json,os,ssl,subprocess,sys,threading
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'))
from test_https import HTTPSLocalTLSTests as Fixture

def main():
    Fixture.setUpClass();server=None;thread=None
    try:
        # Bind only sandbox loopback. If port 443 is unavailable, a test-only
        # port translation is recorded; it never edits the production source.
        try:server=http.server.ThreadingHTTPServer(('127.0.0.1',443),Fixture.server.RequestHandlerClass);translated=False
        except OSError:server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fixture.server.RequestHandlerClass);translated=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(Fixture.root/'server.pem',Fixture.root/'server.key')
        server.socket=context.wrap_socket(server.socket,server_side=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        certdir=Fixture.root/'empty-ca-dir';certdir.mkdir();rows=[]
        for name,trusted,host in [('valid',True,'ufw-test.example'),('wrong_hostname',True,'other-test.example'),('untrusted_CA',False,'ufw-test.example')]:
            source=(ROOT/'lab/https-tools.ps1').read_text('utf-8-sig')
            if translated:source=source.replace(')),443,$null,$null)',f")),{server.server_address[1]},$null,$null)")
            script="\n".join('. '+"'"+str(ROOT/'lab'/p)+"'" for p in ('session-core.ps1','native.ps1','traffic-tools.ps1'))+'\n'+source+'''
$script:realEndpointValidator=(Get-Command HValidateEndpoint).ScriptBlock
# Only the public-IP admission is substituted to allow sandbox loopback.
function HValidateEndpoint($URL,$Address){& $script:realEndpointValidator $URL '9.9.9.9'}
$challenge=[pscustomobject]@{kind='unifiedfw-traffic-1';nonce=('a'*64);request_id=('b'*32);role='REF'}
$r=HReference '__URL__' '127.0.0.1' $challenge
$r|ConvertTo-Json -Compress
'''.replace('__URL__','https://'+host+'/probe.php')
            file=Fixture.root/(name+'.ps1');file.write_text(script)
            env=os.environ.copy();env.pop('SSL_CERT_FILE',None);env.pop('SSL_CERT_DIR',None)
            if trusted:env.update(SSL_CERT_FILE=str(Fixture.root/'ca.pem'),SSL_CERT_DIR=str(certdir))
            completed=subprocess.run(['/data/devtools/pwsh/pwsh','-NoLogo','-NoProfile','-File',str(file)],env=env,capture_output=True,text=True,timeout=20,check=True)
            result=json.loads(completed.stdout.strip().splitlines()[-1]);assert result['connected'] is True,(name,result)
            if name=='valid':assert result['tls_verified'] is True and result['handshake_ok'] is True,(name,result)
            else:assert result['tls_verified'] is False and result['handshake_ok'] is False,(name,result)
            rows.append(dict(case=name,connected=result['connected'],tls_verified=result['tls_verified'],handshake_ok=result['handshake_ok']))
        report=dict(passed=True,backend='Linux PowerShell/.NET SslStream + real localhost TLS HTTP server',cases=rows,public_IP_gate_substituted_for_loopback=True,test_only_port_translation=translated,system_trust_store_changed=False,private_CA_via_child_environment_only=True,windows_executed=False,php_responder_executed=False,external_network_used=False)
        (ROOT/'evidence/https-dotnet-local.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join()
        Fixture.tearDownClass()
if __name__=='__main__':main()
