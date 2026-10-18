"""One-shot hosted Windows startup capture. Exports whitelist metadata only."""
import collections
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from packet_meta import analyze,host

DNS_SCRIPT=r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$r=@{status='not_started';category='none';hresult=0;row_count=0;old_json_shape='not_tested';pairs=@()}
try {
 $rows=@(Get-DnsClientCache | Select-Object -First 2049 Entry,Data)
 $r.row_count=$rows.Count
 $old=$rows | ConvertTo-Json -Compress
 if ([string]::IsNullOrWhiteSpace($old)) {$r.old_json_shape='empty'}
 elseif ($old.TrimStart().StartsWith('[')) {$r.old_json_shape='array'}
 elseif ($old.TrimStart().StartsWith('{')) {$r.old_json_shape='object'}
 elseif ($old.Trim() -eq 'null') {$r.old_json_shape='null'}
 else {$r.old_json_shape='other'}
 $r.pairs=@($rows)
 $r.status='ok'
} catch {
 $r.status='cmdlet_error'
 $allowed=@('NotSpecified','ObjectNotFound','PermissionDenied','ResourceUnavailable','InvalidOperation','InvalidArgument','SecurityError','ParserError','MetadataError')
 $c=[string]$_.CategoryInfo.Category
 if ($allowed -contains $c) {$r.category=$c} else {$r.category='other'}
 $r.hresult=[int]$_.Exception.HResult
}
ConvertTo-Json -InputObject $r -Depth 4 -Compress
'''

def dns_probe(env):
 diag={'status':'not_started','category':'none','hresult':0,'row_count':0,'old_json_shape':'not_tested'};pairs=set()
 try:
  r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',DNS_SCRIPT],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False)
  if r.returncode:diag['status']='process_error';return diag,pairs
  if len(r.stdout)>1024*1024:diag['status']='output_limit';return diag,pairs
  data=json.loads(r.stdout.decode('utf-8-sig'))
  for k in diag:diag[k]=data[k]
  if data['row_count']>2048:diag['status']='row_limit';return diag,pairs
  for row in data['pairs']:
   h=host(row.get('Entry',''))
   try:ip=ipaddress.ip_address(row.get('Data',''))
   except ValueError:continue
   if h and ip.is_global:pairs.add((h,str(ip)))
 except subprocess.TimeoutExpired:diag['status']='timeout'
 except Exception:diag['status']='decode_error'
 return diag,pairs

class Watcher:
 def __init__(self,api,names):self.api=api;self.names=names;self.stop=threading.Event();self.watched={};self.samples=0;self.errors=0;self.limited=False
 def run(self):
  started=time.monotonic()
  while not self.stop.is_set() and time.monotonic()-started<300:
   try:
    raw=self.api(self.names);self.samples+=1
    names={p['ProcessId']:p['Name'].lower() for p in raw['processes']}
    for c in raw['connections']:
     if c['OwningProcess'] not in names or not ipaddress.ip_address(c['RemoteAddress']).is_global or not 1<=c['RemotePort']<=65535:continue
     key=(c['LocalAddress'],c['LocalPort'],c['RemoteAddress'],c['RemotePort'])
     if len(self.watched)>=512 and key not in self.watched:self.limited=True;continue
     self.watched[key]={'pid':c['OwningProcess'],'process_name':names[c['OwningProcess']]}
   except Exception:self.errors+=1
   self.stop.wait(.1)
  if not self.stop.is_set():self.errors+=1

def run_tool(exe,args,env,timeout=20):
 try:
  p=subprocess.run([str(exe),*map(str,args)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
  return p.returncode
 except subprocess.TimeoutExpired:return -1001
 except OSError:return -1002

def observe(obs,out,seconds):
 import native_tcp
 env=obs.clean_environment(os.environ)
 if obs.snapshot(env).get('processes'):raise SystemExit('preexisting_processes_refused')
 run=os.environ.get('GITHUB_RUN_ID','');source=os.environ.get('GITHUB_SHA','')
 if not run.isdigit() or not re.fullmatch('[0-9a-f]{40}',source):raise SystemExit('identity')
 out=Path('output');out.mkdir(exist_ok=True)
 before={'status':'not_started','category':'none','hresult':0,'row_count':0,'old_json_shape':'not_tested'};cache_before=set()
 binary_hints=[]
 capture={'start_code':None,'stop_code':None,'convert_code':None,'etl_bytes':0,'pcapng_bytes':0,'parse_status':'not_attempted','raw_files_exported':False,'requested_etl_megabytes':32,'requested_packet_bytes':1536,'logging_mode':'circular'}
 watcher=Watcher(native_tcp.snapshot,obs.NAMES);thread=threading.Thread(target=watcher.run,daemon=True)
 parsed={'packet_stats':{},'flows':[]};base=None
 with tempfile.TemporaryDirectory(prefix='network-private-',dir=os.environ['RUNNER_TEMP']) as tmp:
  etl=Path(tmp)/'capture.etl';pcap=Path(tmp)/'capture.pcapng';exe=Path(os.environ['SystemRoot'])/'System32'/'pktmon.exe'
  capture['start_code']=run_tool(exe,['start','--capture','--comp','nics','--pkt-size','1536','--file-size','32','--log-mode','circular','--file-name',etl],env)
  if capture['start_code']!=0:
   # Do not spend another startup experiment if capture is unavailable.
   base={'status':'not_launched_capture_failed','error_code':'capture_start_failed'}
  else:
   thread.start()
   try:base=obs.observe(out,seconds,advance_language=True,advance_install=False)
   finally:
    watcher.stop.set();thread.join(timeout=20)
    capture['stop_code']=run_tool(exe,['stop'],env)
   if thread.is_alive():raise SystemExit('watcher_stop_failed')
   if etl.exists():capture['etl_bytes']=etl.stat().st_size
   if capture['stop_code']==0 and 0<capture['etl_bytes']<=64*1024*1024:
    capture['convert_code']=run_tool(exe,['etl2pcap',etl,'--out',pcap],env,60)
    if pcap.exists():capture['pcapng_bytes']=pcap.stat().st_size
    if capture['convert_code']==0 and 0<capture['pcapng_bytes']<=128*1024*1024:
     try:parsed=analyze(pcap,watcher.watched);capture['parse_status']='parsed'
     except Exception:capture['parse_status']='parser_error'
    else:capture['parse_status']='conversion_failed_or_size_limit'
   else:capture['parse_status']='stop_failed_or_etl_size_limit'
  after={'status':'not_started','category':'none','hresult':0,'row_count':0,'old_json_shape':'not_tested'};cache_after=set()
 # Temporary capture directory removed before producing shared output.
 for row in parsed['flows']:
  row['cache_candidates']=sorted(h for h,ip in cache_after if ip==row['address'])[:32]
 report={'schema':'bnet-network-metadata-1','source_commit':source,'run_id':run,'scope':'startup_language_only_no_account_game_or_install_action','capture':capture,'dns_probe_before':before,'dns_probe_after':after,'sampler':{'samples':watcher.samples,'errors':watcher.errors,'flow_limit_hit':watcher.limited},**parsed,'binary_hints':binary_hints,'bootstrap_status':base['status'],'bootstrap_error_code':base['error_code'],
 'limits':{'decryption_performed':False,'keylog_experiment_repeated':False,'raw_headers_urls_bodies_exported':False,'no_hardware_privacy_guarantee':True,'no_game_update_test':True,'sampling_can_miss_connections':True,'tuple_correlation_not_cryptographic_pid_proof':True,'dns_candidates_not_hostname_proof':True,'nic_duplicates_retransmissions_offload_possible':True,'packet_counts_not_requests_or_wire_byte_totals':True,'initial_contiguous_prefix_only':True,'fragments_ipv6_extensions_quic_doh_not_decoded':True,'circular_capture_may_lose_early_packets':True,'sni_may_be_outer_name_under_ech':True,'bootstrap_child_network_hard_byte_cap':False}}
 payload=json.dumps(report,indent=2).encode()
 if len(payload)>1024*1024:raise SystemExit('report_limit')
 (out/'network-metadata.json').write_bytes(payload)
 print(json.dumps({'capture_parse_status':capture['parse_status'],'flow_records':len(parsed['flows']),'bootstrap_status':base['status']}))
 return base
