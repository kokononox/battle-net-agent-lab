"""Read-only BAT06 diagnosis. No hooks, hosts writes, cache flush, or process control."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import threading
import time
from request_audit import BLOCKED,TARGET,classify_addresses,profile_ok

KNOWN=(*BLOCKED,TARGET)

def hosts_entries(text):
    result={h:[] for h in KNOWN};malformed=[]
    for line in text.splitlines():
        parts=line.partition('#')[0].split()
        if len(parts)<2:continue
        try:address=str(ipaddress.ip_address(parts[0]))
        except ValueError:continue
        for raw in parts[1:]:
            name=raw.lower().rstrip('.')
            if name in result and address not in result[name]:result[name].append(address)
            elif name.endswith(':443') and name[:-4] in result and name not in malformed:malformed.append(name)
    return result,malformed

def dns_one(host,q):
    try:
        addresses=sorted({x[4][0] for x in socket.getaddrinfo(host,None,0,socket.SOCK_STREAM)})
        q.put((host,{'resolver_state':classify_addresses(addresses),'resolved_addresses':addresses,'error_code':None}))
    except OSError as exc:
        q.put((host,{'resolver_state':'resolution_failed','resolved_addresses':[],
            'error_code':exc.errno if type(exc.errno) is int else None}))
    except Exception:
        q.put((host,{'resolver_state':'diagnostic_error','resolved_addresses':[],'error_code':None}))

def collect(hosts_path,timeout=20):
    file_state='read';malformed=[];entries={h:[] for h in KNOWN}
    try:
        if hosts_path.stat().st_size>1048576:raise ValueError('hosts_too_large')
        data=hosts_path.read_bytes()
        try:text=data.decode('utf-8-sig')
        except UnicodeError:
            if data.startswith((b'\xff\xfe',b'\xfe\xff')):text=data.decode('utf-16')
            else:raise
        entries,malformed=hosts_entries(text)
    except Exception:file_state='unreadable_or_unrecognized'
    q=queue.Queue()
    for h in KNOWN:threading.Thread(target=dns_one,args=(h,q),daemon=True).start()
    answers={};deadline=time.monotonic()+timeout
    while len(answers)<len(KNOWN) and time.monotonic()<deadline:
        try:h,r=q.get(timeout=max(.01,deadline-time.monotonic()));answers[h]=r
        except queue.Empty:break
    rows=[]
    for h in KNOWN:
        answer=answers.get(h,{'resolver_state':'timeout_unconfirmed','resolved_addresses':[],'error_code':None})
        expected='public_only' if h==TARGET else 'sink_only'
        rows.append({'host':h,'expected_resolver_state':expected,'hosts_addresses':entries[h],
            **answer,'matches_t1_requirement':answer['resolver_state']==expected})
    return {'schema':'t1-dns-diagnostic-1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'hosts_read_state':file_state,'malformed_known_tokens':malformed,
        't1_profile_confirmed':profile_ok({r['host']:r['resolver_state'] for r in rows}),
        'failed_hosts':[r['host'] for r in rows if not r['matches_t1_requirement']], 'rows':rows,
        'hosts_changed':False,'dns_cache_flushed':False,'processes_controlled':False,'hooks_attached':False,
        'automatic_upload':False,'download_or_update_requested':False,
        'limits':['DNS resolver snapshot only; not firewall enforcement','Parallel DNS probes; timeouts are unconfirmed, not proof of blocking','Only the fixed 25 names and their address mappings are exported; unrelated hosts content is omitted']}

def main():
    base=Path(__file__).resolve().parents[1]
    if not (base/'runtime/python.exe').is_file():raise ValueError('extract_into_existing_T1_folder_first')
    print('T1 DNS DIAGNOSTIC ONLY. Keep update PAUSED. No hooks or hosts changes.')
    path=Path(os.environ['SystemRoot'])/'System32/drivers/etc/hosts'
    r=collect(path)
    print('HOSTS read state:',r['hosts_read_state'])
    for row in r['rows']:
        if not row['matches_t1_requirement']:
            print('MISMATCH:',row['host'],'expected='+row['expected_resolver_state'],'actual='+row['resolver_state'],
                'hosts='+','.join(row['hosts_addresses']),'dns='+','.join(row['resolved_addresses']),
                'error='+str(row['error_code']))
    if r['t1_profile_confirmed']:print('DNS profile matches at this instant. This is NOT a no-telemetry guarantee.')
    out=base/'output';out.mkdir(exist_ok=True)
    dest=out/('t1-dns-diagnostic-'+str(time.time_ns())+'.json')
    with dest.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
    print('Send only output/'+dest.name)
    print('This diagnostic NEVER authorizes Resume. Keep update PAUSED pending review.')

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('STOP:',str(exc) if isinstance(exc,ValueError) else 'diagnostic_failed_no_settings_changed')
        raise SystemExit(1)
