"""Fixed IPv4:443 TCP + hostname-validated TLS. No proxy, redirect or retry."""
import http.client,ipaddress,json,re,socket,ssl,time
from urllib.parse import urlsplit
from traffic_common import challenge,public_ipv4,MAX_MESSAGE
MAX_WIRE=32768

def https_endpoint(url,address):
    address=public_ipv4(address)
    if not isinstance(url,str) or len(url)>512:raise ValueError('invalid_https_url')
    try:u=urlsplit(url)
    except ValueError as e:raise ValueError('invalid_https_url') from e
    host=u.hostname or '';path=u.path
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host):raise ValueError('ascii_dns_hostname_required')
    if not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.php',path):raise ValueError('simple_php_path_required')
    if u.scheme!='https' or url!='https://'+host+path:raise ValueError('canonical_https_url_no_credentials_query_fragment_or_port_required')
    return dict(url=url,host=host,path=path,address=address,port=443,transport='https_php')

def verify_dns(config):
    addresses=sorted({x[4][0] for x in socket.getaddrinfo(config['host'],443,socket.AF_INET,socket.SOCK_STREAM)})
    if config['address'] not in addresses:raise ValueError('selected_IP_not_in_hostname_IPv4_DNS; do_not_disable_TLS_or_force_other_IPs')
    return addresses

class _BudgetFile:
    def __init__(self,file,sock,deadline):self.file=file;self.sock=sock;self.deadline=deadline;self.remaining=MAX_WIRE
    def _limit(self,n):
        if self.remaining<=0:raise ValueError('https_wire_size_limit')
        left=self.deadline-time.monotonic()
        if left<=0:raise TimeoutError('https_total_deadline')
        self.sock.settimeout(min(left,3.0))
        return min(self.remaining+1,n if n>=0 else self.remaining+1)
    def _account(self,b):
        self.remaining-=len(b)
        if self.remaining<0:raise ValueError('https_wire_size_limit')
        return b
    def read(self,n=-1):return self._account(self.file.read(self._limit(n)))
    def readline(self,n=-1):return self._account(self.file.readline(self._limit(n)))
    def flush(self):
        if not self.file.closed:self.file.flush()
    def close(self):self.file.close()
class _ResponseSocket:
    def __init__(self,sock,deadline):self.sock=sock;self.deadline=deadline
    def makefile(self,mode):return _BudgetFile(self.sock.makefile(mode),self.sock,self.deadline)

def read_response(sock,deadline,request):
    response=http.client.HTTPResponse(_ResponseSocket(sock,deadline))
    try:
        response.begin()
        if response.status!=200:raise ValueError('https_status_'+str(response.status)+'_not_followed')
        # Reject ambiguous framing, compression and critical duplicate headers.
        for name in ('Content-Length','Transfer-Encoding','Content-Type','Content-Encoding'):
            if len(response.headers.get_all(name,[]))>1:raise ValueError('duplicate_https_header')
        length=response.getheader('Content-Length');transfer=response.getheader('Transfer-Encoding')
        if length is not None and transfer is not None:raise ValueError('ambiguous_https_framing')
        if length is not None and (not re.fullmatch(r'[0-9]{1,5}',length) or int(length)>MAX_MESSAGE):raise ValueError('https_body_size_limit')
        if transfer is not None and transfer.lower()!='chunked':raise ValueError('unsupported_https_transfer_encoding')
        if response.getheader('Content-Encoding','identity').lower()!='identity':raise ValueError('https_compression_not_supported')
        if response.getheader('Content-Type','').split(';')[0].strip().lower()!='application/json':raise ValueError('https_json_content_type_required')
        body=response.read(MAX_MESSAGE+1)
        if len(body)>MAX_MESSAGE:raise ValueError('https_body_size_limit')
        if length is not None and len(body)!=int(length):raise ValueError('https_truncated_body')
        value=json.loads(body.decode('utf-8'))
        if not isinstance(value,dict) or set(value)!=set(request)|{'observed_peer'} or any(value.get(k)!=v for k,v in request.items()):raise ValueError('https_challenge_response_mismatch')
        peer=value['observed_peer']
        if not isinstance(peer,str) or len(peer)>45:raise ValueError('https_server_peer_invalid')
        ipaddress.ip_address(peer)
        return peer
    finally:response.close()

def probe_https(url,address,request):
    cfg=https_endpoint(url,address);challenge(request)
    result=dict(schema='unifiedfw-https-probe-1',transport='https_php',probe_valid=True,request_id=request['request_id'],role=request['role'],connected=False,connection_attempted=False,tls_verified=False,http_status=None,handshake_ok=False,local_address=None,server_observed_peer=None,error=None,error_code=None)
    result['stage']='tls_context_setup'
    start=time.monotonic();deadline=start+8.0;attempted=False
    try:
        context=ssl.create_default_context()
        if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:raise ValueError('TLS_verification_must_remain_enabled')
        context.minimum_version=ssl.TLSVersion.TLSv1_2
    except (OSError,ValueError) as e:
        result.update(probe_valid=False,error='TLS_context_preparation_failed:'+str(e)[:180],elapsed_ms=round((time.monotonic()-start)*1000,1));return result
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as raw:
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError('https_context_preparation_exceeded_deadline')
            raw.settimeout(min(3.0,left));result['stage']='tcp_connect';attempted=True;raw.connect((cfg['address'],443));result['connected']=True;result['local_address']=raw.getsockname()[0]
            raw.settimeout(min(3.0,max(0.1,deadline-time.monotonic())))
            result['stage']='tls_handshake'
            with context.wrap_socket(raw,server_hostname=cfg['host']) as secure:
                result['tls_verified']=True
                body=json.dumps(request,separators=(',',':')).encode('ascii')
                headers=(f"POST {cfg['path']} HTTP/1.1\r\nHost: {cfg['host']}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n").encode('ascii')
                result['stage']='http_send'
                secure.sendall(headers+body)
                result['stage']='http_response_and_echo'
                result['server_observed_peer']=read_response(secure,deadline,request)
                result['http_status']=200;result['handshake_ok']=True;result['stage']='complete'
    except (OSError,ValueError,UnicodeError,http.client.HTTPException) as e:
        if not attempted:result['probe_valid']=False
        result['error']=type(e).__name__+':'+str(e)[:200];result['error_code']=getattr(e,'winerror',None) or getattr(e,'errno',None)
    result['connection_attempted']=attempted
    result['elapsed_ms']=round((time.monotonic()-start)*1000,1)
    return result
