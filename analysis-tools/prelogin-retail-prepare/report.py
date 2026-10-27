"""Strict public summary: no token, response values, paths, UUIDs or arbitrary labels."""
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.append(str(ROOT/'agent-interface-lab'))
import probe
import form_details
import form_update
from retail_protocol import FIELDS,CODES,BLOCKERS
STATUSES={'not_started','discovery_failed','handshake_not_ready','request_failed','existing_products_refused','form_observed','form_schema_unknown','identity_changed','stopped'}
ERRORS={None,'OSError','ValueError','RuntimeError','Stop','other'}
def blank(source,run):
 h=probe.blank();h.update(source_commit=source,run_id=run,run_attempt='1')
 return dict(schema='bnet-retail-prepare-4',source_commit=source,run_id=run,status='not_started',error_kind=None,product='wow',test_profile=dict(region='eu',locale='enUS',platform='win',architecture='x86_64'),bootstrap_pin_match=None,metadata=None,form_details=form_details.blank(),form_update=form_update.blank(),handshake=h,identity_checks=0,temp_image_verifications=0,last_identity_state=None,identity_failure_state=None,local_requests=0,initial_summary_empty=False,initialization_attempted=False,initialization_http_status=None,initialization_response_bytes=0,last_http_status=None,form=dict(form_fields=[],unknown_fields=False,form_schema_valid=False,error_codes={k:None for k in ('agent',*CODES)},blockers=[]),limits=dict(finalization_requested=False,account_login_requested=False,country_fabricated=False,legal_terms_accepted=False,minimum_spec_bypassed=False,game_payload_download_requested=False,game_executed=False,user_install_accessed=False,token_exported=False,raw_response_exported=False,frida_requested=False,hardware_transmission_in_download_phase_proven=False,game_download_without_login_proven=False,initialization_may_trigger_network=True,child_network_hard_byte_cap=False,full_game_download_requested=False))

def validate(r):
 if type(r) is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-retail-prepare-4':raise ValueError('fields')
 if type(r['source_commit']) is not str or re.fullmatch('[0-9a-f]{40}',r['source_commit']) is None or type(r['run_id']) is not str or re.fullmatch('[0-9]{1,30}',r['run_id']) is None:raise ValueError('identity')
 if r['status'] not in STATUSES or r['error_kind'] not in ERRORS or r['product']!='wow' or r['test_profile']!=blank('a'*40,'1')['test_profile']:raise ValueError('enum')
 if r['bootstrap_pin_match'] is not None and type(r['bootstrap_pin_match']) is not bool:raise ValueError('pin')
 form_update.validate(r['form_update'])
 form_details.validate(r['form_details'])
 probe.validate(r['handshake'])
 if any(r['handshake'][k]!=r[k] for k in ('source_commit','run_id')):raise ValueError('handshake_identity')
 if r['handshake']['http_requests_attempted'] and r['bootstrap_pin_match'] is not True:raise ValueError('handshake_pin')
 m=r['metadata']
 if m is not None:
  if type(m) is not dict or set(m)!={'version','build_config','versions_sha256','response_bytes'}:raise ValueError('metadata')
  for k,p in [('version',r'\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,10}'),('build_config','[0-9a-f]{32}'),('versions_sha256','[0-9a-f]{64}')]:
   if type(m[k]) is not str or re.fullmatch(p,m[k]) is None:raise ValueError('metadata_identity')
  if type(m['response_bytes']) is not int or not 0<m['response_bytes']<=1024**2:raise ValueError('metadata_bytes')
 for k,cap in [('identity_checks',64),('temp_image_verifications',64),('local_requests',3),('initialization_response_bytes',65536)]:
  if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('count')
 if r['temp_image_verifications']>r['identity_checks']:raise ValueError('identity_count')
 for k in ('last_identity_state','identity_failure_state'):
  if r[k] is not None and r[k] not in probe.IDENTITY_STATES:raise ValueError('identity_state')
 if r['identity_failure_state'] in ('verified','verified_temp_image'):raise ValueError('failure_state')
 for k in ('initial_summary_empty','initialization_attempted'):
  if type(r[k]) is not bool:raise ValueError('boolean')
 for k in ('initialization_http_status','last_http_status'):
  if r[k] is not None and (type(r[k]) is not int or not 100<=r[k]<=599):raise ValueError('http')
 if r['local_requests'] and (not r['handshake']['authorization_token_present'] or m is None):raise ValueError('session_required')
 if r['initialization_attempted'] and (r['local_requests']not in (2,3) or not r['initial_summary_empty']):raise ValueError('initialization_guard')
 if r['form_update']['status']in {'response_observed','unexpected_finalized'} and (r['handshake']['status']!='handshake_token_observed' or r['identity_checks']<1):raise ValueError('update_identity_evidence')
 if r['form_update']['attempted'] and (r['local_requests']!=3 or not r['initialization_attempted']):raise ValueError('update_request_guard')
 if r['local_requests']==3 and not r['form_update']['attempted']:raise ValueError('extra_request')
 if not r['initialization_attempted'] and (r['initialization_http_status'] is not None or r['initialization_response_bytes']):raise ValueError('no_initialization')
 f=r['form']
 if type(f) is not dict or set(f)!={'form_fields','unknown_fields','form_schema_valid','error_codes','blockers'}:raise ValueError('form_schema')
 for k in ('unknown_fields','form_schema_valid'):
  if type(f[k]) is not bool:raise ValueError('form_boolean')
 if type(f['form_fields']) is not list or any(type(k) is not str or k not in FIELDS for k in f['form_fields']) or len(set(f['form_fields']))!=len(f['form_fields']):raise ValueError('form_fields')
 if type(f['blockers']) is not list or any(type(k) is not str or k not in BLOCKERS for k in f['blockers']) or len(set(f['blockers']))!=len(f['blockers']):raise ValueError('blockers')
 if type(f['error_codes']) is not dict or set(f['error_codes'])!={'agent',*CODES}:raise ValueError('codes')
 for v in f['error_codes'].values():
  if v is not None and (type(v) is not int or not 0<=v<=2**32):raise ValueError('code_type')
 if f['form_schema_valid'] and (f['unknown_fields'] or 'schema_invalid' in f['blockers'] or 'unknown_fields' in f['blockers']):raise ValueError('valid_form')
 if f['form_schema_valid'] and any(k not in f['form_fields'] or f['error_codes'][k] is None for k in ('authentication','min_spec','game_dir')):raise ValueError('required_form_fields')
 for k,b in dict(agent='agent_error',**CODES).items():
  if f['error_codes'][k] and b not in f['blockers']:raise ValueError('code_blocker')
 if 'eula' in f['form_fields'] and 'eula_review_pending' not in f['blockers']:raise ValueError('legal_guard')
 expected=blank('a'*40,'1')['limits']
 if type(r['limits']) is not dict or set(r['limits'])!=set(expected) or any(type(r['limits'][k]) is not bool or r['limits'][k] is not v for k,v in expected.items()):raise ValueError('limits')
 if r['form_details']['status']=='observed' and (not r['initialization_attempted'] or r['initialization_http_status'] not in (200,201) or not r['initialization_response_bytes']):raise ValueError('details_evidence')
 if r['status'] in {'form_observed','form_schema_unknown'}:
  if not (r['initialization_attempted'] and r['initialization_http_status'] in (200,201) and r['initialization_response_bytes']>0 and r['handshake']['status']=='handshake_token_observed' and r['identity_failure_state'] is None and r['identity_checks']>0 and r['last_identity_state'] in {'verified','verified_temp_image'}):raise ValueError('result_evidence')
  if f['form_schema_valid']!=(r['status']=='form_observed'):raise ValueError('result_schema')
 return r

def load(raw):
 if len(raw)>65536:raise ValueError('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return validate(json.loads(raw,object_pairs_hook=unique))
if __name__=='__main__':
 r=load(Path(sys.argv[1]).read_bytes());p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
