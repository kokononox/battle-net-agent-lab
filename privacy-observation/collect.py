"""Fresh hosted VM only. Sanitized TCP observations, DNS candidates and TLS-keylog capability.
No packet/payload/key export. No login, install-button action or game request.
"""
import collections
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

SCHEMA = 'bnet-startup-privacy-observation-1'
MAX_ENDPOINTS = 512
MAX_DNS = 2048
STATES = {'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB','other'}
LABELS = {'CLIENT_RANDOM','CLIENT_EARLY_TRAFFIC_SECRET','CLIENT_HANDSHAKE_TRAFFIC_SECRET','SERVER_HANDSHAKE_TRAFFIC_SECRET','CLIENT_TRAFFIC_SECRET_0','SERVER_TRAFFIC_SECRET_0','EXPORTER_SECRET','EARLY_EXPORTER_SECRET'}

def dns_rows(raw):
    if len(raw) > 1024*1024: raise ValueError('dns_body_limit')
    rows = json.loads(raw.decode('utf-8-sig'))
    if rows is None: rows=[]
    if isinstance(rows,dict): rows=[rows]
    if not isinstance(rows,list) or len(rows)>MAX_DNS: raise ValueError('dns_row_limit')
    result=set()
    for r in rows:
        if not isinstance(r,dict): continue
        host=str(r.get('Entry','')).lower().rstrip('.')
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',host): continue
        if any(len(p)>63 or not p for p in host.split('.')): continue
        try: ip=ipaddress.ip_address(r.get('Data',''))
        except ValueError: continue
        if ip.is_global: result.add((host,str(ip)))
    return result

def dns_snapshot(env):
    # Cache only: no reverse-DNS or active resolver requests from the collector.
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); @(Get-DnsClientCache | Select-Object -First 2049 Entry,Data) | ConvertTo-Json -Compress"],
        env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)
    if p.returncode: raise ValueError('dns_snapshot_failed')
    return dns_rows(p.stdout)

def keylog_summary(path):
    result={'file_created':False,'bytes':0,'recognized_line_counts':{},'truncated':False,
            'keys_exported':False,'decryption_attempted':False,'request_content_observed':False}
    if not path.exists(): return result
    result['file_created']=True; result['bytes']=path.stat().st_size
    result['truncated']=result['bytes']>1024*1024
    counts=collections.Counter()
    with path.open('rb') as f:
        for line in f.read(1024*1024).splitlines():
            parts=line.split()
            if len(parts)!=3:continue
            try:label=parts[0].decode('ascii')
            except UnicodeError:continue
            if label in LABELS and re.fullmatch(rb'[0-9a-fA-F]{64}',parts[1]) and re.fullmatch(rb'[0-9a-fA-F]{64,128}',parts[2]):counts[label]+=1
    result['recognized_line_counts']=dict(counts)
    return result

class Sampler:
    def __init__(self,snapshot,names):
        self.snapshot=snapshot;self.names=names;self.endpoints={};self.samples=0;self.errors=0
        self.limited=False;self.stop=threading.Event();self.started=time.monotonic()
    def consume(self,raw,elapsed):
        procs={p['ProcessId']:str(p['Name']).lower() for p in raw.get('processes',[]) if p.get('Name','').lower() in self.names and type(p.get('ProcessId')) is int}
        for c in raw.get('connections',[]):
            if c.get('OwningProcess') not in procs:continue
            try:ip=ipaddress.ip_address(c.get('RemoteAddress',''))
            except ValueError:continue
            port=c.get('RemotePort')
            if not ip.is_global or type(port) is not int or not 1<=port<=65535:continue
            key=(c['OwningProcess'],procs[c['OwningProcess']],str(ip),port)
            if key not in self.endpoints:
                if len(self.endpoints)>=MAX_ENDPOINTS:self.limited=True;continue
                self.endpoints[key]={'pid':key[0],'process_name':key[1],'address':key[2],'port':port,'first_seconds':elapsed,'last_seconds':elapsed,'observations':0,'states':[]}
            r=self.endpoints[key];r['last_seconds']=elapsed;r['observations']+=1
            state=c.get('State','other');state=state if state in STATES else 'other'
            if state not in r['states']:r['states'].append(state)
    def run(self):
        while not self.stop.is_set() and time.monotonic()-self.started<240:
            try:self.consume(self.snapshot(self.names),round(time.monotonic()-self.started,3));self.samples+=1
            except Exception:self.errors+=1
            self.stop.wait(.25)
        if not self.stop.is_set(): self.errors+=1 # bounded sampler window expired

def main():
    if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Windows' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or os.environ.get('PRIVACY_ONCE')!='startup-privacy-20261018-a1':raise SystemExit('fresh_hosted_once_required')
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
    import observe_agent as obs
    import native_windows
    source=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','')
    if not re.fullmatch('[0-9a-f]{40}',source) or not run.isdigit():raise SystemExit('invalid_run_identity')
    out=Path('output');out.mkdir(exist_ok=True)
    keypath=Path(os.environ['RUNNER_TEMP'])/('tls-private-'+run+'.keys')
    if keypath.exists() or obs.snapshot(obs.clean_environment(os.environ)).get('processes'):raise SystemExit('preexisting_state_refused')
    original=obs.clean_environment
    def clean_with_keylog(source):
        env=original(source);env['SSLKEYLOGFILE']=str(keypath);return env
    obs.clean_environment=clean_with_keylog
    env=original(os.environ)
    dns_errors=0
    try:before=dns_snapshot(env)
    except Exception:before=set();dns_errors+=1
    monitor=Sampler(native_windows.snapshot,obs.NAMES);thread=threading.Thread(target=monitor.run,daemon=True)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat()
    thread.start()
    try:
        # Existing constrained language-page helper only; no install/legal/account action.
        base=obs.observe(out,120,advance_language=True,advance_install=False)
    finally:
        monitor.stop.set();thread.join(timeout=20)
    if thread.is_alive():raise SystemExit('sampler_stop_failed')
    try:after=dns_snapshot(env)
    except Exception:after=set();dns_errors+=1
    dns=after-before if dns_errors==0 else set()
    endpoints=list(monitor.endpoints.values())
    for row in endpoints:
        row['new_dns_cache_candidates']=sorted(h for h,ip in dns if ip==row['address'])[:32]
    try:tls=keylog_summary(keypath)
    finally:
        if keypath.exists():keypath.unlink()
    report={'schema':SCHEMA,'source_commit':source,'run_id':run,'started_utc':start,
        'scope':'signed_bootstrap_startup_and_language_page_only_not_game_update',
        'sampler':{'interval_seconds':.25,'samples':monitor.samples,'errors':monitor.errors,'endpoint_limit_hit':monitor.limited,'dns_snapshot_errors':dns_errors,'new_dns_address_pairs':len(dns)},
        'endpoints':endpoints,'tls_keylog_capability':tls,
        'bootstrap_status':base['status'],'bootstrap_error_code':base['error_code'],
        'limits':{'tcp_only':True,'udp_quic_not_observed':True,'short_connections_may_be_missed':True,'process_attribution_by_basename_and_pid_not_signature':True,'dns_candidates_not_process_attribution':True,'dns_shared_ip_not_host_proof':True,'no_packet_capture':True,'no_payload_inspection':True,'no_zero_telemetry_claim':True,'child_network_hard_byte_cap':False,'no_account_or_game_actions':True},
        'collection_status':'completed' if monitor.samples and not monitor.errors and not dns_errors and not monitor.limited else 'partial'}
    data=json.dumps(report,indent=2).encode()
    if len(data)>512*1024:raise SystemExit('report_size_limit')
    (out/'privacy-observation.json').write_bytes(data)
    print(json.dumps({'collection_status':report['collection_status'],'endpoint_count':len(endpoints),'keylog_file_created':tls['file_created']}))

if __name__=='__main__':main()
