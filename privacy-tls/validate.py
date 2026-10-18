import ipaddress
import json
from pathlib import Path
import re
import sys
from body_meta import FIELD_ALIASES,FORMATS,METHODS
from monitor import APIS,BUFFER_APIS,MODULE_NAMES
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privacy-network'))
from packet_meta import host

def exact(d,keys):
 if type(d) is not dict or set(d)!=set(keys.split()):raise ValueError('schema')
def integer(v,lo=0,hi=2**40):
 if type(v) is not int or not lo<=v<=hi:raise ValueError('integer')
def boolean(v):
 if type(v) is not bool:raise ValueError('boolean')
def sha(v):
 if v is not None and (type(v) is not str or not re.fullmatch('[a-f0-9]{64}',v)):raise ValueError('sha')
def hostname(v):
 if v is not None and (type(v) is not str or host(v)!=v):raise ValueError('host')
def validate(r):
 exact(r,'schema source_commit run_id scope tool_version selftest bootstrap_pin_match processes events monitor_stats status error_code limits')
 if r['schema']!='bnet-live-tls-buffer-observation-1' or r['scope']!='fresh_vm_startup_no_login_game_or_install_action' or r['tool_version']!='17.24.2':raise ValueError('scope')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['bootstrap_pin_match'] is not None:boolean(r['bootstrap_pin_match'])
 t=r['selftest'];exact(t,'passed stage loopback_only synthetic_events_excluded_from_real_evidence');boolean(t['passed'])
 if t['stage'] not in ('not_started','worker_start','attach','script_load','await_event','complete','event_not_observed') or t['loopback_only'] is not True or t['synthetic_events_excluded_from_real_evidence'] is not True:raise ValueError('selftest')
 if type(r['processes']) is not list or len(r['processes'])>8:raise ValueError('processes')
 identities={}
 for p in r['processes']:
  exact(p,'pid process_name image_basename_match sha256 image_bytes path_category agent_directory_version signature_accepted authenticode_valid expected_blizzard_publisher module_status network_module_categories attach_status failure_phase error_kind numeric_error_code installed_hooks buffer_events script_error_count')
  integer(p['pid'],1,2**32-1);sha(p['sha256']);integer(p['image_bytes'],0,128*1024*1024)
  if p['process_name'] not in ('agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'):raise ValueError('process_name')
  for k in ('image_basename_match','signature_accepted','authenticode_valid','expected_blizzard_publisher'):boolean(p[k])
  if p['path_category'] not in ('battle_net_agent_tree','agent_version_tree','temporary_tree','program_files_tree','other'):raise ValueError('path_category')
  if p['agent_directory_version'] is not None:integer(p['agent_directory_version'],0,9999999999)
  if p['module_status'] not in ('not_tested','ok','unavailable','limit'):raise ValueError('modules')
  if type(p['network_module_categories']) is not list or len(p['network_module_categories'])>20 or any(x not in MODULE_NAMES|{'openssl_ssl_module','openssl_crypto_module','libcurl_module'} for x in p['network_module_categories']):raise ValueError('module_names')
  if p['attach_status'] not in ('not_attempted','image_refused','signature_refused','identity_changed','attached','process_gone_or_probe_failed'):raise ValueError('attach')
  if p['failure_phase'] not in (None,'identity','hash','signature','frida_attach','identity_recheck','script_load'):raise ValueError('phase')
  if p['error_kind'] not in (None,'ProcessNotFoundError','PermissionDeniedError','TimedOutError','OperationCancelledError','ProcessNotRespondingError','InvalidOperationError','OSError','FileNotFoundError','Exception','TypeError','NotSupportedError','TransportError','other'):raise ValueError('error_kind')
  if p['numeric_error_code'] is not None:integer(p['numeric_error_code'],-2**31,2**31-1)
  if type(p['installed_hooks']) is not list or len(p['installed_hooks'])>len(APIS) or any(x not in APIS for x in p['installed_hooks']):raise ValueError('hooks')
  integer(p['buffer_events'],0,512);integer(p['script_error_count'])
  if p['attach_status']=='attached' and not(p['signature_accepted'] and p['image_basename_match'] and p['authenticode_valid'] and p['expected_blizzard_publisher']):raise ValueError('unsigned_attach')
  identities[(p['pid'],p['sha256'])]=p
 if type(r['events']) is not list or len(r['events'])>512:raise ValueError('events')
 for e in r['events']:
  exact(e,'pid process_sha256 api declared_length sample_bytes buffer_truncated api_success request_host_hint request_method_hint format compression decoded_truncated field_name_hints keys_examined http_host http_method')
  integer(e['pid'],1,2**32-1);sha(e['process_sha256'])
  identity=identities.get((e['pid'],e['process_sha256']))
  if identity is None or not identity['signature_accepted']:raise ValueError('event_identity')
  if e['api'] not in BUFFER_APIS:raise ValueError('api')
  integer(e['declared_length'],0,67108864);integer(e['sample_bytes'],0,16384);integer(e['keys_examined'],0,512)
  for k in ('buffer_truncated','api_success','decoded_truncated'):boolean(e[k])
  for k in ('request_host_hint','http_host'):hostname(e[k])
  for k in ('request_method_hint','http_method'):
   if e[k] not in METHODS|{None}:raise ValueError('method')
  if e['format'] not in FORMATS or e['compression'] not in ('none','gzip','deflate'):raise ValueError('format')
  if type(e['field_name_hints']) is not list or len(e['field_name_hints'])>len(FIELD_ALIASES) or any(x not in set(FIELD_ALIASES.values()) for x in e['field_name_hints']):raise ValueError('field_hints')
 stats=r['monitor_stats'];exact(stats,'snapshots errors process_limit_hit dropped_events')
 for k in ('snapshots','errors','dropped_events'):integer(stats[k])
 boolean(stats['process_limit_hit'])
 if r['status'] not in ('not_started','collector_returned','stopped'):raise ValueError('status')
 if r['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['error_code']):raise ValueError('error_code')
 exact(r['limits'],'raw_values_headers_bodies_exported paths_exported tls_verification_changed api_results_or_buffers_modified plaintext_is_api_input_not_proof_of_delivery field_names_are_hints_not_hardware_value_proof only_known_exported_apis_observed late_attach_and_event_caps_can_miss_data loaded_module_not_proof_of_use instrumentation_can_change_timing_or_behavior full_update_or_transfer_test')
 false={'raw_values_headers_bodies_exported','paths_exported','tls_verification_changed','api_results_or_buffers_modified','full_update_or_transfer_test'}
 for k,v in r['limits'].items():
  if v is not (k not in false):raise ValueError('limits')
 if r['processes'] and not r['selftest']['passed']:raise ValueError('selftest_not_passed')
 return r
if __name__=='__main__':
 src,dst=map(Path,sys.argv[1:])
 if src.stat().st_size>1024*1024:raise SystemExit('report_limit')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 r=validate(json.loads(src.read_text(encoding='utf-8'),object_pairs_hook=unique));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
