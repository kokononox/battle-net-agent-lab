import ipaddress
import json
from pathlib import Path
import re
import sys
from run import PIN,TARGET

def validate(r):
 keys='schema runner_image_version windows_build source_commit run_id mode target_domain expected_bootstrap_sha256 bootstrap_pin_enforced pin_match hosts_changed hosts_restored flush_before_succeeded flush_after_succeeded resolution_before resolution_at_launch target_public_addresses_before launch_precondition_passed capture_invoked outcome error_code scope'.split()
 if type(r) is not dict or set(r)!=set(keys):raise ValueError('schema')
 if type(r['windows_build']) is not int or not 10000<=r['windows_build']<=99999:raise ValueError('windows_build')
 if r['runner_image_version'] is not None and not re.fullmatch('[0-9.]{1,40}',r['runner_image_version']):raise ValueError('image')
 if r['schema']!='bnet-hosts-ab-1' or r['scope']!='startup_only_not_update_or_payload_privacy_proof':raise ValueError('scope')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['mode'] not in ('baseline','block_telemetry') or r['target_domain']!=TARGET or r['expected_bootstrap_sha256']!=PIN or r['bootstrap_pin_enforced'] is not True:raise ValueError('experiment')
 if r['pin_match'] is not None and type(r['pin_match']) is not bool:raise ValueError('pin')
 for k in ('hosts_changed','hosts_restored','flush_before_succeeded','flush_after_succeeded','launch_precondition_passed','capture_invoked'):
  if type(r[k]) is not bool:raise ValueError('boolean')
 for k in ('resolution_before','resolution_at_launch'):
  if r[k] not in ('not_tested','failed','timeout','public_only','loopback_only','mixed_or_other'):raise ValueError('resolution')
 if type(r['target_public_addresses_before']) is not list or len(r['target_public_addresses_before'])>32:raise ValueError('addresses')
 for a in r['target_public_addresses_before']:
  if type(a) is not str or not ipaddress.ip_address(a).is_global:raise ValueError('address')
 if r['outcome'] not in ('not_started','collector_returned','stopped'):raise ValueError('outcome')
 if r['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['error_code']):raise ValueError('error')
 if r['mode']=='baseline' and (r['hosts_changed'] or r['hosts_restored']):raise ValueError('baseline_mutated')
 if r['launch_precondition_passed']:
  if not r['flush_before_succeeded'] or r['resolution_before']!='public_only':raise ValueError('precondition')
  if r['mode']=='block_telemetry' and (not r['hosts_changed'] or not r['flush_after_succeeded'] or r['resolution_at_launch']!='loopback_only'):raise ValueError('block')
 if r['capture_invoked'] and not r['launch_precondition_passed']:raise ValueError('capture_without_precondition')
 return r
if __name__=='__main__':
 src,dst=map(Path,sys.argv[1:])
 if src.stat().st_size>16384:raise SystemExit('size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 r=validate(json.loads(src.read_text(encoding='utf-8'),object_pairs_hook=unique));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
