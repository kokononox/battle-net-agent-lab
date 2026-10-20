"""Selected, trusted Blizzard image: bounded domain and outgoing-content observations.
Attach only. Never bypass trust/anti-cheat, spawn user targets, or alter TLS/network policy.
"""
from collections import Counter
import base64
import ctypes
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
import urllib.parse
import zlib
from observer import ContentCollector
from launcher_destinations import Tracker,choose_exe,file_hash,path_key,process_rows,process_identity
from native_tcp import tcp_connections
from safepaths import safe_path

BASE=Path(__file__).resolve().parents[1]
MAX_DOMAIN_EVENTS=8192
MAX_BINARY_BYTES=32*1024**2


def valid_domain(name):
 if not isinstance(name,str):return None
 name=name.lower().rstrip('.')
 if not 1<=len(name)<=253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in name.split('.')):return None
 try:ipaddress.ip_address(name);return None
 except ValueError:return name


def json_structure(value,depth=0):
 """Keys and types only. No scalar values, credentials, session IDs, raw URLs or bodies."""
 if depth>3:return {'type':'depth_limit'}
 if isinstance(value,dict):
  result={}
  for k,v in list(value.items())[:48]:
   # Arbitrary/user-generated key names are not exported.
   if not isinstance(k,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',k):continue
   if re.search(r'token|password|secret|cookie|authorization|session|ticket|credential|email|account',k,re.I):
    result['[sensitive_field_redacted]']={'type':'redacted'}
   else:result[k]=json_structure(v,depth+1)
  return {'type':'object','fields':result,'field_count':len(value),'fields_truncated':len(value)>48}
 if isinstance(value,list):return {'type':'array','length':len(value),'item_shapes':[json_structure(v,depth+1) for v in value[:3]]}
 if value is None:return {'type':'null'}
 if isinstance(value,bool):return {'type':'boolean'}
 if isinstance(value,(int,float)):return {'type':'number'}
 return {'type':'string' if isinstance(value,str) else 'unknown'}


def scan_prefix(raw,refs):
 # Bounded RAM-only checks. No blob, decoded text, CPU or BIOS value leaves this function.
 raw=bytes(raw[:16384]);samples=[raw]
 try:samples.append(urllib.parse.unquote_to_bytes(raw.replace(b'+',b' ')))
 except Exception:pass
 if raw.startswith(b'\x1f\x8b'):
  try:samples.append(zlib.decompressobj(31).decompress(raw,65536))
  except zlib.error:pass
 hits=[]
 for category,values in refs.items():
  if any(v.encode(codec) in s for v in values for codec in ('utf-8','utf-16-le') for s in samples):hits.append(category)
 kind='tls_record_candidate' if len(raw)>2 and raw[0] in (20,21,22,23) and raw[1]==3 else 'http1_candidate' if re.match(rb'^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|CONNECT) ',raw) else 'unclassified_binary_or_text'
 return {'hardware_literal_categories':sorted(hits),'format_hint':kind}


def body_structure(r):
 raw=base64.b64decode(r['body_sample_base64']);headers=dict(r['headers']);enc=headers.get('content-encoding','').lower()
 if enc in ('gzip','deflate'):
  try:raw=zlib.decompressobj(31 if enc=='gzip' else 15).decompress(raw,65536)
  except zlib.error:return {'type':'compressed_unreadable'}
 elif enc and enc!='identity':return {'type':'unsupported_content_encoding'}
 if not raw:return {'type':'empty'}
 if len(raw)>65536:return {'type':'body_limit'}
 try:return json_structure(json.loads(raw.decode('utf-8')))
 except (ValueError,UnicodeError,RecursionError):pass
 if 'application/x-www-form-urlencoded' in headers.get('content-type','').lower():
  try:
   pairs=urllib.parse.parse_qsl(raw.decode('utf-8'),max_num_fields=128)
   return json_structure(dict(pairs))
  except (ValueError,UnicodeError):pass
 return {'type':'unparsed_body_values_not_exported'}


def install_body_summary():
 # Narrow, process-local wrapper; original parser/redaction/in-memory hardware matching retained.
 import request_audit
 original=request_audit.summarize_request
 def summarize(r,process,channel,needle,refs=None):
  result=original(r,process,channel,needle,refs)
  shape=body_structure(r)
  if len(json.dumps(shape))>2048:
   shape={'type':'body_structure_export_limit','top_level_type':shape.get('type'),
    'top_level_field_names':list(shape.get('fields',{}))[:16]}
  result['body_structure']=shape
  result['path_hint']='/tpr/...' if result['path_class']=='tpr' else '/data' if r['target'].split('?',1)[0]=='/data' else 'other_path_not_exported'
  return result
 request_audit.summarize_request=summarize


class DomainSelftestCollector(ContentCollector):
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.hook_filename='game_hook.js'
  self.control_sni=False;self.control_prefix=False
 def message(self,key,msg,data):
  p=msg.get('payload',{}) if msg.get('type')=='send' else {}
  if p.get('kind')=='domain_meta' and p.get('api')=='TLS_ClientHello_SNI':
   peer=p.get('peer') or {}
   if p.get('domain')=='selftest.invalid' and peer.get('address')=='127.0.0.1':self.control_sni=True
  if p.get('kind')=='binary_prefix':self.control_prefix=True
  super().message(key,msg,data)
 def control_metadata(self):
  return {'synthetic_clienthello_sni_observed':self.control_sni,'prefix_hook_observed':self.control_prefix,
   'synthetic_clienthello_not_tls_decryption':True,'dns_hooks_positive_control_tested':False}


class GameCollector(ContentCollector):
 def __init__(self,frida,refs,path,sha):
  super().__init__(frida,refs)
  self.refs=dict(refs);self.tracker=Tracker(path,sha,identity_fn=process_identity)
  self.live={};self.hook_filename='game_hook.js';self.selected_target_gate=self.gate
  self.selected_expected_hashes={};self.domain_events=[];self.domain_hooks={};self.domain_limit=False
  self.binary_counts=Counter();self.binary_bytes=0;self.binary_limit=False;self.binary_errors=0
  self.target_errors=[];self.discovery_errors=0

 def gate(self,pid,name,info):
  item=self.live.get(pid)
  return bool(item and item[0]==(pid,info['creation']) and item[1]['path']==path_key(info['path']) and item[1]['name']==name)

 def message(self,key,msg,data):
  p=msg.get('payload',{}) if msg.get('type')=='send' else {}
  with self.lock:
   if p.get('kind')=='domain_hook_installed':
    if p.get('api') in {'getaddrinfo','GetAddrInfoW','DnsQuery_A','DnsQuery_W','WinHttpConnect'}:
     self.domain_hooks.setdefault(key,set()).add(p['api'])
    return
   if p.get('kind')=='domain_meta':
    domain=valid_domain(p.get('domain'));api=p.get('api')
    if not domain or api not in {'getaddrinfo','GetAddrInfoW','DnsQuery_A','DnsQuery_W','WinHttpConnect','TLS_ClientHello_SNI'}:self.meta_errors+=1;return
    if len(self.domain_events)>=MAX_DOMAIN_EVENTS:self.domain_limit=True;return
    row={'process_index':key,'api':api,'domain':domain,'elapsed_seconds':round(time.monotonic()-self.clock,2),
     'evidence':'same_socket_clienthello_outer_name' if api=='TLS_ClientHello_SNI' else 'process_name_lookup_not_socket_bound' if api!='WinHttpConnect' else 'http_connect_target_not_socket_bound',
     'remote_address':None,'remote_port':None,'lookup_return_code':p.get('return_code') if type(p.get('return_code')) is int else None}
    peer=p.get('peer')
    if api=='TLS_ClientHello_SNI' and peer:
     try:
      addr=str(ipaddress.ip_address(peer['address']));port=peer['port']
      if type(port)is not int or not 0<=port<=65535:raise ValueError()
      row['remote_address']=addr;row['remote_port']=port
     except (ValueError,KeyError,TypeError):self.meta_errors+=1;return
    self.domain_events.append(row);return
   is_binary=p.get('kind')=='binary_prefix'
   is_sspi=p.get('kind')=='input' and p.get('api')=='EncryptMessage'
   if is_binary or is_sspi:
    try:
     raw=bytes(data or b'')
     if len(raw)>16384 or p.get('api') not in {'send','WSASend','EncryptMessage'}:raise ValueError()
     if self.binary_bytes+len(raw)>MAX_BINARY_BYTES:self.binary_limit=True
     else:
      self.binary_bytes+=len(raw);meta=scan_prefix(raw,self.refs)
      # Input observation before API success is NOT proof of network send or server receipt.
      group=(key,p['api'],meta['format_hint'],tuple(meta['hardware_literal_categories']))
      if len(self.binary_counts)<4096 or group in self.binary_counts:self.binary_counts[group]+=1
      else:self.binary_limit=True
    except (ValueError,TypeError):self.binary_errors+=1
    if is_binary:return
   super().message(key,msg,data)

 def run(self):
  while not self.stop.is_set():
   try:
    self.live=self.tracker.discover(process_rows())
    for pid,(token,d) in list(self.live.items()):
     if self.stop.is_set():break
     if d['role']=='selected_exe':self.selected_expected_hashes[token]=self.tracker.sha
     try:self.attach(pid,d['name'])
     except (OSError,ValueError):self.discovery_errors+=1
    pid_keys={pid:k for (pid,creation),k in self.private_paths.items() if self.rows[k]['status']=='attached'}
    active=set(self.live)&set(pid_keys)
    for conn in tcp_connections(active) if active else []:
     pid=conn['OwningProcess'];k=pid_keys.get(pid)
     if not k:continue
     info=process_identity(pid)
     if self.private_paths.get((pid,info['creation']))!=k:continue
     addr=ipaddress.ip_address(conn['RemoteAddress'])
     if not addr.is_global:continue
     fk=(k,str(addr),conn['RemotePort'])
     if fk not in self.flows:
      if len(self.flows)>=1024:self.flow_limit=True;continue
      self.flows[fk]={'process_index':k,'remote_address':str(addr),'remote_port':conn['RemotePort'],'sample_observations':0}
     self.flows[fk]['sample_observations']+=1
   except ValueError as e:
    self.target_errors.append(str(e) if re.fullmatch('[a-z_]{1,100}',str(e)) else 'selected_target_error')
    self.stop.set()
   except OSError:self.sampler_errors+=1
   except Exception:self.sampler_errors+=1
   self.stop.wait(.2)

 def ready(self):
  return any(token in self.selected_expected_hashes and self.rows[k]['status']=='attached'
   and self.rows[k]['hook_ready'] and {'send','WSASend'}<=set(self.rows[k]['installed_hooks'])
   for token,k in list(self.private_paths.items()))

 def extra_report(self):
  a=self.audit_report()
  seen={}
  for r in self.domain_events:
   k=(r['process_index'],r['api'],r['domain'],r['remote_address'],r['remote_port'],r['lookup_return_code'])
   if k not in seen:seen[k]=dict(r,observations=0)
   seen[k]['observations']+=1
  # Only directly evidenced HTTP Host/socket pairs or SNI/socket observations form bindings.
  bindings=[]
  for r in a['requests']:
   if r['remote_address'] and r['destination_evidence']=='getpeername_same_socket_alias':
    bindings.append({'process_index':r['process_index'],'domain':r['host'],'remote_address':r['remote_address'],
     'remote_port':r['remote_port'],'evidence':'plaintext_http_host_same_socket'})
  for r in seen.values():
   if r['api']=='TLS_ClientHello_SNI' and r['remote_address']:
    bindings.append({k:r[k] for k in ('process_index','domain','remote_address','remote_port','evidence')})
  unique={tuple(sorted(b.items())):b for b in bindings}
  return {'domain_observations':list(seen.values()),'direct_domain_ip_bindings':list(unique.values()),
   'domain_hooks_installed':[{'process_index':k,'apis':sorted(v)} for k,v in self.domain_hooks.items()],
   'binary_and_sspi_prefix_checks':[{'process_index':k,'api':api,'format_hint':fmt,'hardware_literal_categories':list(cats),'api_input_observations':n,'network_send_proven':False} for (k,api,fmt,cats),n in self.binary_counts.items()],
   'prefix_bytes_inspected_in_ram':self.binary_bytes,'prefix_or_domain_limit_hit':self.binary_limit or self.domain_limit,
   'prefix_errors':self.binary_errors,'target_errors':self.target_errors,'discovery_errors':self.discovery_errors,
   'content_scope':'bounded_HTTP1_and_SSPI_plaintext_plus_Winsock_prefix_markers_not_general_game_protocol_decryption'}

 def close(self):
  super().close()
  self.refs.clear()


def save(report):
 out=safe_path(BASE/'output');out.mkdir(exist_ok=True)
 raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode()
 if len(raw)>8*1024**2:raise ValueError('report_size_limit')
 p=safe_path(out/('game-content-'+str(time.time_ns())+'.json'))
 with p.open('xb') as f:f.write(raw)
 print('\nREPORT:',str(p));print('Send this JSON only. No automatic upload occurred.')


def main():
 report={'schema':'selected-game-content-1','version':'0.1.8','status':'preflight','error_code':None,
 'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'selected_exe_name':None,'selected_exe_sha256':None,
 'native_helper':None,'native_selftest':None,'ready_announced':False,'observation':None,'audit':None,'content_and_domains':None,
 'hardware_reference_categories_available':[],'capture_start_mode':'manual_after_stable_login_screen','manual_attach_requested':False,
 'limits':{'passive_not_prevention':True,'initial_launch_traffic_covered':False,'early_requests_may_be_missed':True,'full_tls_coverage_proven':False,
 'sspi_positive_control_passed':False,'udp_quic_http2_proprietary_protocol_fully_covered':False,
 'no_credentials_raw_bodies_urls_or_hardware_values_exported':True,'domain_names_and_json_field_names_exported':True,
 'no_dns_requests_or_network_policy_changes_by_observer':True,'signature_verification_may_use_network':True,
 'signed_blizzard_targets_only':True,'no_target_process_spawn_suspend_termination_or_anti_cheat_bypass':True,
 'process_injection_can_affect_stability':True,'runtime_state_not_identical_to_uninstrumented':True,
 'no_only_download_zero_telemetry_or_server_receipt_verdict':True,'native_windows_qualification_completed_by_builder':False}}
 c=None;refs={};lock=None
 try:
  if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
  if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator')
  from main import integrity,mutex,compile_helper
  integrity();lock=mutex()
  print('Game Content + Domains 0.1.8 - experimental observation, NOT a privacy firewall.')
  print('The game may already be at its login screen. Attach starts ONLY after your Enter marker.')
  print('Attach-only hooks can affect stability/timing. Initial launch traffic will NOT be covered.')
  print('Only valid Blizzard-signed files are attached. No trust, anti-cheat or TLS bypass.')
  print('Credentials/body values stay out of the report; domain and JSON field names are reported.')
  path=choose_exe()
  if path is None:report['status']='cancelled';return
  sha=file_hash(path);report['selected_exe_name']=path.name;report['selected_exe_sha256']=sha
  if input('Experimental isolated test accepted. Type START: ').strip()!='START':report['status']='cancelled';return
  report['native_helper']=compile_helper()
  from core import signature
  sig=signature(path);report['selected_signature']=sig
  if not sig['valid'] or not sig['blizzard']:raise ValueError('selected_file_not_trusted_blizzard_no_attach')
  import frida
  if frida.__version__!='17.24.2':raise ValueError('unexpected_frida_version')
  from native_selftest import run
  print('Running owned-loopback positive control...')
  report['native_selftest']=run(frida,collector_type=DomainSelftestCollector,fixture_name='game_fixture.py')
  if not report['native_selftest']['passed']:raise ValueError('loopback_selftest_failed')
  install_body_summary()
  from hardware import references
  refs=references();report['hardware_reference_categories_available']=sorted(refs)
  report['status']='waiting_for_manual_attach'
  print('Open the selected game yourself, if not already open. Let the login screen settle.')
  print('No hooks are attached to the game yet. Do NOT enter account credentials for this test.')
  answer=input('At stable login screen: press Enter to attach; Q cancels: ').strip().lower()
  if answer=='q':report['status']='cancelled_before_target_attach';return
  if answer!='':raise ValueError('press_enter_or_q_only')
  present=Tracker(path,sha)
  if not present.discover(process_rows()):raise ValueError('selected_exe_not_running_at_manual_trigger')
  report['manual_attach_requested']=True
  c=GameCollector(frida,refs,path,sha);c.phase='after_manual_login_screen_marker'
  c.start();report['status']='waiting_for_selected_exe'
  print('Manual attach requested. Q stops observation ONLY, not the game.')
  import msvcrt
  end_wait=time.monotonic()+180;window=None;failed_notice=False
  while True:
   now=time.monotonic()
   if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':report['status']='user_stopped';break
   if c.target_errors:raise ValueError(c.target_errors[0])
   failed=[r for r in list(c.rows.values()) if r['status']=='not_attached']
   if failed and not c.ready():
    # A launcher-like bootstrap EXE can exit during trust verification.
    # Do not retry the same PID/token or bypass any denied access. Await a new instance only.
    if any(r.get('exception_type')!='ProcessNotFoundError' for r in failed):
     raise ValueError('selected_attach_refused_or_failed_see_process_stage')
    if not failed_notice:
     print('Initial process exited before attachment. Waiting for a new instance; no access bypass.')
     failed_notice=True
   if c.ready() and window is None:
    window=now;report['ready_announced']=True;report['status']='observing'
    print('READY: selected-process hooks active. Recording up to 120 seconds.')
    print('TLS/custom protocol may remain unreadable. Keep this an isolated test.')
   if window is None and now>=end_wait:raise ValueError('selected_exe_not_observed_or_hooks_not_ready')
   if window is not None and now-window>=120:report['status']='observation_ended';break
   time.sleep(.1)
 except KeyboardInterrupt:report['status']='interrupted'
 except Exception as e:
  report['status']='stopped';report['error_code']=str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(e)) else 'local_preflight_or_capture_failed'
  print('STOP:',report['error_code'])
 finally:
  if c:
   try:
    c.close();report['observation']=c.report();report['audit']=c.audit_report();report['content_and_domains']=c.extra_report()
   except Exception:report['status']='stopped';report['error_code']='finalize_failed'
  refs.clear()
  print('Observer ended; game/update were NOT paused or closed. Close them manually if needed.')
  save(report)

if __name__=='__main__':main()
