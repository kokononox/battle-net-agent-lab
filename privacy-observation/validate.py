"""Whitelist-only sanitizer; never copy private logs, key files or arbitrary text."""
import ipaddress
import json
from pathlib import Path
import re
import sys
from collect import SCHEMA,STATES,LABELS

def exact(d,keys):
 if type(d) is not dict or set(d)!=set(keys.split()):raise ValueError('schema')
def integer(x,low,high):
 if type(x) is not int or not low<=x<=high:raise ValueError('integer')
def number(x):
 if type(x) not in (int,float) or not 0<=x<=1200:raise ValueError('number')
def validate(r):
 exact(r,'schema source_commit run_id started_utc scope sampler endpoints tls_keylog_capability bootstrap_status bootstrap_error_code limits collection_status')
 if r['schema']!=SCHEMA or not re.fullmatch('[0-9a-f]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if not re.fullmatch(r'[0-9T:.+Z-]{20,40}',r['started_utc']):raise ValueError('utc')
 if r['scope']!='signed_bootstrap_startup_and_language_page_only_not_game_update':raise ValueError('scope')
 if r['collection_status'] not in ('completed','partial'):raise ValueError('status')
 if r['bootstrap_status'] not in ('stopped','agent_process_observed','bootstrapper_observed_agent_not_observed'):raise ValueError('bootstrap')
 if r['bootstrap_error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['bootstrap_error_code']):raise ValueError('error')
 s=r['sampler'];exact(s,'interval_seconds samples errors endpoint_limit_hit dns_snapshot_errors new_dns_address_pairs')
 if s['interval_seconds']!=.25 or type(s['endpoint_limit_hit']) is not bool:raise ValueError('sampler')
 for k in ('samples','errors'):integer(s[k],0,10000)
 integer(s['dns_snapshot_errors'],0,2);integer(s['new_dns_address_pairs'],0,2048)
 if type(r['endpoints']) is not list or len(r['endpoints'])>512:raise ValueError('endpoints')
 for e in r['endpoints']:
  exact(e,'pid process_name address port first_seconds last_seconds observations states new_dns_cache_candidates')
  integer(e['pid'],1,2**32-1);integer(e['port'],1,65535);integer(e['observations'],1,100000)
  if e['process_name'] not in {'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'}:raise ValueError('process')
  if not ipaddress.ip_address(e['address']).is_global:raise ValueError('ip')
  number(e['first_seconds']);number(e['last_seconds'])
  if type(e['states']) is not list or not 1<=len(e['states'])<=len(STATES) or any(x not in STATES for x in e['states']):raise ValueError('states')
  hs=e['new_dns_cache_candidates']
  if type(hs) is not list or len(hs)>32 or any(type(h) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}',h) for h in hs):raise ValueError('hosts')
 t=r['tls_keylog_capability'];exact(t,'file_created bytes recognized_line_counts truncated keys_exported decryption_attempted request_content_observed')
 for k in ('file_created','truncated'):
  if type(t[k]) is not bool:raise ValueError('tls_bool')
 for k in ('keys_exported','decryption_attempted','request_content_observed'):
  if t[k] is not False:raise ValueError('private_export')
 integer(t['bytes'],0,2**40)
 if type(t['recognized_line_counts']) is not dict or any(k not in LABELS for k in t['recognized_line_counts']):raise ValueError('labels')
 for v in t['recognized_line_counts'].values():integer(v,1,100000)
 exact(r['limits'],'tcp_only udp_quic_not_observed short_connections_may_be_missed process_attribution_by_basename_and_pid_not_signature dns_candidates_not_process_attribution dns_shared_ip_not_host_proof no_packet_capture no_payload_inspection no_zero_telemetry_claim child_network_hard_byte_cap no_account_or_game_actions')
 for k,v in r['limits'].items():
  if v is not (False if k=='child_network_hard_byte_cap' else True):raise ValueError('limits')
 return r
if __name__=='__main__':
 src,dst=map(Path,sys.argv[1:])
 if src.stat().st_size>512*1024:raise SystemExit('report_limit')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 r=validate(json.loads(src.read_text(encoding='utf-8'),object_pairs_hook=unique))
 dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
