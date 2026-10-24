"""Bounded IPv4 TCP challenge protocol and pure acceptance matrix. No firewall calls."""
import ipaddress,json,re,socket,time
KIND='unifiedfw-traffic-1'
MAX_MESSAGE=2048
ROLES=('A','B','REF')

def endpoint(address,port):
    if not isinstance(address,str) or not re.fullmatch(r'[0-9.]{7,15}',address):raise ValueError('literal_public_ipv4_required_no_dns')
    a=ipaddress.IPv4Address(address)
    if not a.is_global or a.is_multicast or a.is_reserved:raise ValueError('public_unicast_ipv4_required')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('unprivileged_test_port_1024_65535_required')
    return str(a),port

def challenge(value):
    if not isinstance(value,dict) or set(value)!={'kind','nonce','request_id','role'} or value['kind']!=KIND or value['role'] not in ROLES:raise ValueError('invalid_challenge_schema')
    for key,size in (('nonce',64),('request_id',32)):
        if not isinstance(value[key],str) or not re.fullmatch('[a-f0-9]{'+str(size)+'}',value[key]):raise ValueError('invalid_challenge_identifier')
    return value

def line(sock,limit=MAX_MESSAGE):
    data=bytearray()
    while len(data)<limit:
        block=sock.recv(1)
        if not block:raise ValueError('peer_closed_before_newline')
        if block==b'\n':return json.loads(data.decode('utf-8'))
        data.extend(block)
    raise ValueError('response_too_large')

def probe(address,port,request,timeout=2.5):
    address,port=endpoint(address,port);challenge(request)
    if not isinstance(timeout,(float,int)) or not 0.1<=timeout<=5:raise ValueError('invalid_probe_timeout')
    result=dict(schema='unifiedfw-tcp-probe-1',probe_valid=True,request_id=request['request_id'],role=request['role'],connected=False,handshake_ok=False,local_address=None,server_observed_peer=None,error=None,error_code=None)
    start=time.monotonic()
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout);s.connect((address,port));result['connected']=True;result['local_address']=s.getsockname()[0]
            s.sendall((json.dumps(request,separators=(',',':'))+'\n').encode('ascii'))
            response=line(s)
            if not isinstance(response,dict) or any(response.get(k)!=v for k,v in request.items()):raise ValueError('challenge_response_mismatch')
            peer=response.get('observed_peer')
            if not isinstance(peer,str):raise ValueError('missing_observed_peer')
            ipaddress.IPv4Address(peer)
            result['handshake_ok']=True;result['server_observed_peer']=peer
    except (OSError,ValueError,UnicodeError) as e:
        result['error']=type(e).__name__+':'+str(e)[:180];result['error_code']=getattr(e,'winerror',None) or getattr(e,'errno',None)
    result['elapsed_ms']=round((time.monotonic()-start)*1000,1)
    return result

def classify(report):
    """A refused/timeout connection alone NEVER proves successful enforcement."""
    expected={'baseline':set(),'only_A':{'A'},'only_B':{'B'},'both':{'A','B'}}
    phases=report.get('phases')
    if not isinstance(phases,list) or [p.get('name') for p in phases]!=list(expected):return dict(outcome='inconclusive',reason='missing_or_out_of_order_phases')
    inconclusive=[];failures=[];seen_ids=set()
    for p in phases:
        records=p.get('during',[]);post=p.get('after_restore',[])
        for label,rows in (('during',records),('after_restore',post)):
            if not isinstance(rows,list) or len(rows)!=9 or any(not isinstance(r,dict) or r.get('role') not in ROLES or type(r.get('round')) is not int for r in rows):return dict(outcome='inconclusive',reason='invalid_probe_matrix')
            if sorted((r.get('role'),r.get('round')) for r in rows)!=[(role,i) for role in ROLES for i in range(3)]:
                return dict(outcome='inconclusive',reason='incomplete_or_duplicate_probe_matrix:'+p['name']+':'+label)
            if any(r.get('probe_valid') is not True for r in rows):return dict(outcome='inconclusive',reason='probe_process_or_execution_failed')
            ids=[r.get('request_id') for r in rows]
            if any(not isinstance(i,str) or not re.fullmatch('[a-f0-9]{32}',i) or i in seen_ids for i in ids) or len(set(ids))!=9:return dict(outcome='inconclusive',reason='reused_or_invalid_request_identifier')
            seen_ids.update(ids)
            if any(type(r.get('connected')) is not bool or type(r.get('handshake_ok')) is not bool for r in rows):return dict(outcome='inconclusive',reason='invalid_probe_flags')
            if any(r['handshake_ok'] and not r['connected'] for r in rows):return dict(outcome='inconclusive',reason='contradictory_probe_flags')
        # Every phase must restore exactly before its post probes.
        if p.get('baseline_strict_equal') is not True or p.get('restored') is not True:inconclusive.append(p['name']+':restore_not_verified')
        for r in records:
            blocked=r['role'] in expected[p['name']]
            if blocked:
                if r['connected']:failures.append(p['name']+':blocked_image_connected:'+r['role'])
            elif not r['handshake_ok']:inconclusive.append(p['name']+':control_or_allowed_probe_failed:'+r['role'])
        if any(not r['handshake_ok'] for r in post):inconclusive.append(p['name']+':post_restore_connectivity_not_recovered')
    if failures:return dict(outcome='failed',reason='blocked_executable_connected',details=failures)
    if inconclusive:return dict(outcome='inconclusive',reason='availability_or_restore_not_verified',details=inconclusive)
    return dict(outcome='passed',scope='fresh_direct_ipv4_tcp_connections_for_two_bundled_images_only',whitelist_tested=False,vpn_route_verified=False,outside_vpn_guard_tested=False,udp_tested=False,packet_capture_performed=False,no_leak_certified=False)
