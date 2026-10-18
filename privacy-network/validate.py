"""Strict metadata whitelist; no arbitrary text, raw payload or secret fields."""
import ipaddress
import json
from pathlib import Path
import re
import sys
from packet_meta import host

def exact(d,keys):
 if type(d) is not dict or set(d)!=set(keys.split()):raise ValueError('schema')
def num(v,lo=0,hi=2**40):
 if type(v) is not int or not lo<=v<=hi:raise ValueError('integer')
def public(v):
 if type(v) is not str or not ipaddress.ip_address(v).is_global:raise ValueError('address')
def hostname(v):
 if v is not None and (type(v) is not str or host(v)!=v):raise ValueError('hostname')
def diag(d):
 exact(d,'status category hresult row_count old_json_shape')
 if d['status'] not in ('not_started','ok','cmdlet_error','process_error','output_limit','row_limit','timeout','decode_error'):raise ValueError('dns_status')
 if d['category'] not in ('none','NotSpecified','ObjectNotFound','PermissionDenied','ResourceUnavailable','InvalidOperation','InvalidArgument','SecurityError','ParserError','MetadataError','other'):raise ValueError('dns_category')
 if d['old_json_shape'] not in ('not_tested','empty','array','object','null','other'):raise ValueError('dns_shape')
 num(d['hresult'],-2**31,2**31-1);num(d['row_count'],0,2049)
def validate(r):
 exact(r,'schema source_commit run_id scope capture dns_probe_before dns_probe_after sampler packet_stats flows binary_hints bootstrap_status bootstrap_error_code limits')
 if r['schema']!='bnet-network-metadata-1' or r['scope']!='startup_language_only_no_account_game_or_install_action':raise ValueError('scope')
 if not re.fullmatch('[0-9a-f]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 c=r['capture'];exact(c,'start_code stop_code convert_code etl_bytes pcapng_bytes parse_status raw_files_exported requested_etl_megabytes requested_packet_bytes logging_mode')
 for k in ('start_code','stop_code','convert_code'):
  if c[k] is not None:num(c[k],-2**31,2**32-1)
 for k in ('etl_bytes','pcapng_bytes'):num(c[k])
 if c['parse_status'] not in ('not_attempted','parsed','parser_error','conversion_failed_or_size_limit','stop_failed_or_etl_size_limit'):raise ValueError('parse_status')
 if c['raw_files_exported'] is not False or c['requested_etl_megabytes']!=32 or c['requested_packet_bytes']!=1536 or c['logging_mode']!='circular':raise ValueError('capture_limits')
 diag(r['dns_probe_before']);diag(r['dns_probe_after'])
 s=r['sampler'];exact(s,'samples errors flow_limit_hit');num(s['samples']);num(s['errors'])
 if type(s['flow_limit_hit']) is not bool:raise ValueError('flow_limit')
 if type(r['packet_stats']) is not dict or not set(r['packet_stats'])<={'packets','truncated_packets','unparsed_block_types','unsupported_or_non_ip_packets','dns_pair_limit_hit','dns_parse_errors','tcp_parse_errors','flow_limit_hit','prefix_memory_limit_hit'}:raise ValueError('stats')
 for v in r['packet_stats'].values():num(v)
 if type(r['flows']) is not list or len(r['flows'])>512:raise ValueError('flows')
 for f in r['flows']:
  exact(f,'process_name pid address port matched_outbound_packet_observations prefix_gap prefix_limit_hit dns_candidates tls_sni http_host http_method cache_candidates')
  if f['process_name'] not in ('agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'):raise ValueError('process')
  num(f['pid'],1,2**32-1);num(f['port'],1,65535);public(f['address']);num(f['matched_outbound_packet_observations'])
  for k in ('prefix_gap','prefix_limit_hit'):
   if type(f[k]) is not bool:raise ValueError('prefix')
  for k in ('tls_sni','http_host'):hostname(f[k])
  if f['http_method'] not in (None,'GET','POST','HEAD','PUT','OPTIONS','CONNECT','DELETE','PATCH'):raise ValueError('method')
  for k in ('dns_candidates','cache_candidates'):
   if type(f[k]) is not list or len(f[k])>32:raise ValueError('host_list')
   for h in f[k]:
    if h is None:raise ValueError('null_host')
    hostname(h)
 if type(r['binary_hints']) is not list or len(r['binary_hints'])>2:raise ValueError('binary_hints')
 for b in r['binary_hints']:
  exact(b,'role sha256 fixed_string_hints')
  if b['role'] not in ('bootstrap','agent_file_candidate') or not re.fullmatch('[0-9a-f]{64}',b['sha256']):raise ValueError('binary_identity')
  exact(b['fixed_string_hints'],'schannel.dll secur32.dll winhttp.dll wininet.dll libssl libcurl sslkeylogfile')
  if any(type(v) is not bool for v in b['fixed_string_hints'].values()):raise ValueError('binary_hint_bool')
 if r['bootstrap_status'] not in ('agent_process_observed','bootstrapper_observed_agent_not_observed','stopped','not_launched_capture_failed'):raise ValueError('bootstrap')
 if r['bootstrap_error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['bootstrap_error_code']):raise ValueError('error')
 l=r['limits'];exact(l,'decryption_performed keylog_experiment_repeated raw_headers_urls_bodies_exported no_hardware_privacy_guarantee no_game_update_test sampling_can_miss_connections tuple_correlation_not_cryptographic_pid_proof dns_candidates_not_hostname_proof nic_duplicates_retransmissions_offload_possible packet_counts_not_requests_or_wire_byte_totals initial_contiguous_prefix_only fragments_ipv6_extensions_quic_doh_not_decoded circular_capture_may_lose_early_packets sni_may_be_outer_name_under_ech bootstrap_child_network_hard_byte_cap')
 false={'decryption_performed','keylog_experiment_repeated','raw_headers_urls_bodies_exported','bootstrap_child_network_hard_byte_cap'}
 for k,v in l.items():
  if v is not (k not in false):raise ValueError('limits')
 return r
if __name__=='__main__':
 src,dst=map(Path,sys.argv[1:])
 if src.stat().st_size>1024*1024:raise SystemExit('report_size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 r=validate(json.loads(src.read_text(encoding='utf-8'),object_pairs_hook=unique));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
