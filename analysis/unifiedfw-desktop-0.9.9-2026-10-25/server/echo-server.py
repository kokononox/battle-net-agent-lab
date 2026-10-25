#!/usr/bin/env python3
"""Temporary bounded challenge responder. Run ONLY on a test server you control.
No authentication, shell, file-transfer, TLS or proxy service. No firewall changes.
"""
import argparse,ipaddress,json,re,socket,time
KIND='unifiedfw-traffic-1'
def serve(bind,port,seconds,max_connections):
    bind=str(ipaddress.IPv4Address(bind))
    if not 1024<=port<=65535 or not 30<=seconds<=1800 or not 1<=max_connections<=300:raise ValueError('invalid_test_limits')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind((bind,port));listener.listen(8);listener.settimeout(0.5)
        finish=time.monotonic()+seconds;handled=0
        print(json.dumps(dict(listening=bind,port=port,expires_in_seconds=seconds,max_connections=max_connections)),flush=True)
        while time.monotonic()<finish and handled<max_connections:
            try:conn,peer=listener.accept()
            except socket.timeout:continue
            handled+=1
            with conn:
                conn.settimeout(2);data=bytearray();ok=False
                try:
                    while len(data)<512:
                        b=conn.recv(1)
                        if not b:raise ValueError('closed')
                        if b==b'\n':break
                        data.extend(b)
                    else:raise ValueError('oversize')
                    q=json.loads(data.decode('ascii'))
                    if not isinstance(q,dict) or set(q)!={'kind','nonce','request_id','role'} or q['kind']!=KIND or q['role'] not in ('A','B','REF'):raise ValueError('schema')
                    if not isinstance(q['nonce'],str) or not re.fullmatch('[a-f0-9]{64}',q['nonce']) or not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise ValueError('identifier')
                    response=dict(q,observed_peer=peer[0]);conn.sendall((json.dumps(response,separators=(',',':'))+'\n').encode('ascii'));ok=True
                except (OSError,ValueError,UnicodeError):pass
                print(json.dumps(dict(at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),peer=peer[0],accepted_challenge=ok,connection_number=handled)),flush=True)
        print(json.dumps(dict(stopped=True,handled_connections=handled)),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=39443);p.add_argument('--seconds',type=int,default=900);p.add_argument('--max-connections',type=int,default=180);a=p.parse_args()
    try:serve(a.bind,a.port,a.seconds,a.max_connections)
    except KeyboardInterrupt:print('Stopped by operator.')
