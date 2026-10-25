"""C0: qualify repeatable client installation before testing removal of any activity."""
import re
from signature_observation import STATUSES as PROBE_STATUSES
BRANCH='research/battlenet-minimal-install-isolation-2026-10-25'
APPROVAL='lab: approved minimal Battle.net install C0 20261025-p2'
SETUP_SHA='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
SETUP_BYTES=4700880
CASE='C0d-verified-install-baseline'
REPLICAS={'r1','r2','r3'}
VERSION_STATES={'unobserved','missing','wrong_type','format_rejected','accepted'}
BINARY_VERSION_STATES={'accepted','no_resource','native_error','invalid_fixed_info','unstable_file'}
STATUSES={'not_started','stopped','bounded_install_not_verified','installed_by_defined_gate'}
PHASES={'guard','baseline','download','identity','native_gate','launch','observe','cleanup','complete'}
KNOWN_NAMES={'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe'}
ACTION_STATUSES=set('not_attempted not_requested pending no_targets ambiguous_window process_mismatch page_mismatch forbidden_text signature_refused executable_identity_refused pattern_unavailable page_changed page_confirmed continue_attempted continued timeout helper_failed output_rejected native_exception journal_failed window_mismatch page_not_language control_ambiguous selection_failed selection_attempted selection_confirmed forbidden_control name_too_long unsafe_name language_group_missing continue_ambiguous continue_missing language_group_ambiguous'.split())
UI_KEYS={'language','legal','account','installation_options','progress','error'}
CHECKS={'registry_key_found','registry_location_match','version_evidence_verified','client_running','account_signal_seen','signed_launcher','signed_client','setup_absent','stable_layout_20_seconds'}
def authorized(env,platform):
 return (platform=='win32' and env.get('GITHUB_ACTIONS')=='true' and env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('RUNNER_OS')=='Windows' and env.get('GITHUB_REF')=='refs/heads/'+BRANCH and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('BNET_MINIMAL_INSTALL')==APPROVAL and env.get('BNET_CASE')==CASE and env.get('BNET_REPLICA') in REPLICAS)
def installed(checks,launched):
 return launched is True and set(checks)==CHECKS and all(checks[k] is True for k in CHECKS)
def layout_ready(checks):
 # File-layout stability must not depend on an unrelated registry version field.
 return all(checks.get(k) is True for k in ('signed_launcher','signed_client'))
def blank(env):
 return dict(schema='bnet-minimal-install-c0d-1',case=CASE,installation_gate='signed_binary_version_v1',binary_probe_counts={},binary_probe_failures=[],last_sample_process_names=[],replica=env.get('BNET_REPLICA',''),started_at=None,ended_at=None,registry_version_state='unobserved',source_commit=env.get('GITHUB_SHA',''),run_id=env.get('GITHUB_RUN_ID',''),status='not_started',phase='guard',error_code=None,target_launched=False,installer={},native_ui_gate=False,language_attempted=False,install_attempted=False,language_status='not_attempted',install_status='not_attempted',samples=0,snapshot_errors=0,gui_errors=0,known_process_counts={},public_endpoints=[],endpoints_truncated=False,install_checks={k:False for k in sorted(CHECKS)},client_binaries=[],cleanup_attempted=False,observer_seconds=0,native_options_probes=0,native_options_last_status='not_attempted',ui_signal_seen={k:False for k in sorted(UI_KEYS)},ui_signal_last={k:False for k in sorted(UI_KEYS)},intervention='none',login_attempted=False,game_download_requested=False,raw_payloads_exported=False,all_processes_observed=False,all_network_observed=False,necessity_tested=False,telemetry_blocked=False)
def validate(v):
 expected=set(blank({}))
 if type(v) is not dict or set(v)!=expected or v['schema']!='bnet-minimal-install-c0d-1' or v['case']!=CASE:raise ValueError('report_schema')
 if not re.fullmatch('[a-f0-9]{40}',v['source_commit']) or not re.fullmatch('[0-9]{1,30}',v['run_id']):raise ValueError('report_identity')
 if v['replica'] not in REPLICAS or v['registry_version_state'] not in VERSION_STATES:raise ValueError('replica_or_version_state')
 from datetime import datetime
 for k in ('started_at','ended_at'):
  if v[k] is not None:
   if type(v[k]) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',v[k]):raise ValueError('timestamp')
   datetime.strptime(v[k],'%Y-%m-%dT%H:%M:%SZ')
 if v['ended_at'] is not None and (v['started_at'] is None or v['ended_at']<v['started_at']):raise ValueError('timestamp_order')
 if v['target_launched'] and v['started_at'] is None:raise ValueError('launch_timestamp')
 if v['installation_gate']!='signed_binary_version_v1':raise ValueError('installation_gate')
 if type(v['binary_probe_counts']) is not dict or not set(v['binary_probe_counts'])<=PROBE_STATUSES or any(type(n) is not int or not 0<=n<=2000 for n in v['binary_probe_counts'].values()):raise ValueError('binary_probe_counts')
 if type(v['binary_probe_failures']) is not list or len(v['binary_probe_failures'])>12:raise ValueError('binary_probe_failures')
 for x in v['binary_probe_failures']:
  if type(x) is not dict or set(x)!={'kind','status','exit_code','trust_status','elapsed_seconds'} or x['kind'] not in ('launcher','client') or x['status'] not in PROBE_STATUSES-{'accepted','waiting_stability'}:raise ValueError('binary_probe_failure')
  if type(x['elapsed_seconds']) is not int or not 0<=x['elapsed_seconds']<=700:raise ValueError('probe_elapsed')
  for field in ('exit_code','trust_status'):
   if x[field] is not None and (type(x[field]) is not int or not -2**31<=x[field]<2**31):raise ValueError('probe_code')
 if type(v['last_sample_process_names']) is not list or len(v['last_sample_process_names'])>6 or len(set(v['last_sample_process_names']))!=len(v['last_sample_process_names']) or not set(v['last_sample_process_names'])<=KNOWN_NAMES:raise ValueError('last_processes')
 if v['status'] not in STATUSES or v['phase'] not in PHASES:raise ValueError('report_status')
 if v['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',v['error_code']):raise ValueError('error_code')
 flags=('target_launched','native_ui_gate','language_attempted','install_attempted','endpoints_truncated','cleanup_attempted','login_attempted','game_download_requested','raw_payloads_exported','all_processes_observed','all_network_observed','necessity_tested','telemetry_blocked')
 if any(type(v[k]) is not bool for k in flags):raise ValueError('boolean')
 for k in flags[-7:]:
  if v[k] is not False:raise ValueError('scope_or_claim')
 if v['intervention']!='none':raise ValueError('baseline_has_no_intervention')
 for k,cap in [('samples',240),('snapshot_errors',240),('gui_errors',240),('observer_seconds',700),('native_options_probes',30)]:
  if type(v[k]) is not int or not 0<=v[k]<=cap:raise ValueError('report_count')
 if set(v['install_checks'])!=CHECKS or any(type(x) is not bool for x in v['install_checks'].values()):raise ValueError('checks')
 if type(v['known_process_counts']) is not dict or not set(v['known_process_counts'])<=KNOWN_NAMES or any(type(x) is not int or not 0<=x<=10000 for x in v['known_process_counts'].values()):raise ValueError('process_counts')
 if type(v['public_endpoints']) is not list or len(v['public_endpoints'])>512:raise ValueError('endpoints')
 import ipaddress
 for e in v['public_endpoints']:
  if type(e) is not dict or set(e)!={'process_name','ip','port','samples'} or e['process_name'] not in KNOWN_NAMES:raise ValueError('endpoint_schema')
  if not isinstance(e['ip'],str) or len(e['ip'])>45:raise ValueError('endpoint_ip')
  if e['ip']!='nonpublic' and not ipaddress.ip_address(e['ip']).is_global:raise ValueError('endpoint_ip')
  if type(e['port']) is not int or not 0<=e['port']<=65535 or type(e['samples']) is not int or not 1<=e['samples']<=10000:raise ValueError('endpoint_count')
 if type(v['installer']) is not dict or set(v['installer']) not in (set(),{'sha256','bytes','signature_accepted','matches_pin'}):raise ValueError('installer_schema')
 if v['installer']:
  i=v['installer']
  if not re.fullmatch('[a-f0-9]{64}',i['sha256']) or type(i['bytes']) is not int or not 0<i['bytes']<=128*1024**2 or any(type(i[k]) is not bool for k in ('signature_accepted','matches_pin')):raise ValueError('installer_values')
  if i['matches_pin']!=(i['sha256']==SETUP_SHA and i['bytes']==SETUP_BYTES):raise ValueError('pin_crossfoot')
 if v['target_launched'] and (not v['installer'] or not v['installer']['matches_pin'] or not v['installer']['signature_accepted'] or not v['native_ui_gate']):raise ValueError('launch_gate')
 for key in ('ui_signal_seen','ui_signal_last'):
  if type(v[key]) is not dict or set(v[key])!=UI_KEYS or any(type(x) is not bool for x in v[key].values()):raise ValueError('ui_signals')
 for key in ('language_status','install_status','native_options_last_status'):
  if not isinstance(v[key],str) or v[key] not in ACTION_STATUSES:raise ValueError('action_status')
 if type(v['client_binaries']) is not list or len(v['client_binaries'])>8:raise ValueError('binaries')
 for b in v['client_binaries']:
  if type(b) is not dict or set(b)!={'kind','sha256','bytes','signature_accepted','file_version','version_status'} or b['kind'] not in ('launcher','client'):raise ValueError('binary_schema')
  if not re.fullmatch('[a-f0-9]{64}',b['sha256']) or type(b['bytes']) is not int or not 0<b['bytes']<=128*1024**2 or type(b['signature_accepted']) is not bool:raise ValueError('binary_values')
  if b['version_status'] not in BINARY_VERSION_STATES:raise ValueError('binary_version_status')
  if b['version_status']=='accepted':
   if type(b['file_version']) is not str or not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}',b['file_version']):raise ValueError('binary_version')
   parts=list(map(int,b['file_version'].split('.')))
   if max(parts)>65535 or not any(parts):raise ValueError('binary_version')
  elif b['file_version']!='':raise ValueError('binary_version')
 for kind in ('launcher','client'):
  if v['install_checks']['signed_'+kind] and not any(b['kind']==kind and b['signature_accepted'] for b in v['client_binaries']):raise ValueError('binary_check_not_backed')
 if v['install_checks']['version_evidence_verified']:
  for kind in ('launcher','client'):
   candidates=[b for b in v['client_binaries'] if b['kind']==kind]
   if len(candidates)!=1 or not candidates[0]['signature_accepted'] or candidates[0]['version_status']!='accepted':raise ValueError('version_evidence_not_backed')
 if v['install_checks']['client_running'] and 'battle.net.exe' not in v['last_sample_process_names']:raise ValueError('client_running_not_backed')
 if v['install_checks']['account_signal_seen'] and not v['ui_signal_seen']['account']:raise ValueError('account_signal_not_backed')
 if v['install_checks']['setup_absent'] and ('battle.net-setup.exe' in v['last_sample_process_names'] or not v['samples']):raise ValueError('setup_absence_not_backed')
 if (v['language_attempted'] or v['install_attempted']) and not v['target_launched']:raise ValueError('action_without_launch')
 if v['status']=='installed_by_defined_gate' and (not installed(v['install_checks'],v['target_launched']) or v['error_code'] is not None or v['snapshot_errors'] or not v['cleanup_attempted'] or v['phase'] not in ('cleanup','complete') or v['samples']==0):raise ValueError('false_install_success')
 return v
