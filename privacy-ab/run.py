"""Controlled A/B experiment, fresh disposable hosted VM only. Never run on user PC."""
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import sys
import threading

TARGET='telemetry-in.battle.net'
PIN='de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf'
PATCH=b'\r\n# privacy-ab-c1 disposable hosted VM only\r\n127.0.0.1 telemetry-in.battle.net\r\n::1 telemetry-in.battle.net\r\n'

def classify(addresses):
 ips={ipaddress.ip_address(a) for a in addresses}
 if not ips:return 'failed',[]
 public=sorted(str(a) for a in ips if a.is_global)
 if all(a.is_loopback for a in ips):return 'loopback_only',[]
 if all(a.is_global for a in ips):return 'public_only',public
 return 'mixed_or_other',public

def resolve():
 q=queue.Queue(maxsize=1)
 def worker():
  try:q.put(classify(r[4][0] for r in socket.getaddrinfo(TARGET,443,type=socket.SOCK_STREAM)))
  except Exception:q.put(('failed',[]))
 t=threading.Thread(target=worker,daemon=True);t.start()
 try:return q.get(timeout=10)
 except queue.Empty:return 'timeout',[]

def flush():
 api=ctypes.WinDLL('dnsapi',use_last_error=True).DnsFlushResolverCache
 api.argtypes=[];api.restype=ctypes.c_int
 return bool(api())

def contains_target(b):
 text=b.decode('utf-8-sig')
 return any(TARGET in line.split('#',1)[0].lower().split()[1:] for line in text.splitlines())

def main():
 if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Windows' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or os.environ.get('PRIVACY_AB_ONCE')!='ab-20261018-c1':raise SystemExit('fresh_hosted_once_required')
 mode=os.environ.get('AB_MODE')
 if mode not in ('baseline','block_telemetry'):raise SystemExit('mode')
 source=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','')
 if not re.fullmatch('[a-f0-9]{40}',source) or not run.isdigit():raise SystemExit('identity')
 root=Path(__file__).resolve().parents[1]
 sys.path.insert(0,str(root/'privacy-network'));sys.path.insert(0,str(root/'scripts'))
 import observe_agent as obs
 import harness
 report={'schema':'bnet-hosts-ab-1','runner_image_version':os.environ.get('ImageVersion') if re.fullmatch('[0-9.]{1,40}',os.environ.get('ImageVersion','')) else None,'windows_build':sys.getwindowsversion().build,'source_commit':source,'run_id':run,'mode':mode,'target_domain':TARGET,'expected_bootstrap_sha256':PIN,'bootstrap_pin_enforced':True,'pin_match':None,'hosts_changed':False,'hosts_restored':False,'flush_before_succeeded':False,'flush_after_succeeded':False,'resolution_before':'not_tested','resolution_at_launch':'not_tested','target_public_addresses_before':[],'launch_precondition_passed':False,'capture_invoked':False,'outcome':'not_started','error_code':None,'scope':'startup_only_not_update_or_payload_privacy_proof'}
 hosts=Path(os.environ['SystemRoot'])/'System32'/'drivers'/'etc'/'hosts';original=None;modified=None
 out=Path('output');out.mkdir(exist_ok=True)
 original_fetch=obs.fetch_setup
 def pinned_fetch(destination):
  result=original_fetch(destination)
  report['pin_match']=result['sha256']==PIN
  if not report['pin_match']:
   destination.unlink(missing_ok=True)
   raise obs.LabError('bootstrap_pin_mismatch_refused')
  return result
 obs.fetch_setup=pinned_fetch
 try:
  if obs.snapshot(obs.clean_environment(os.environ)).get('processes'):raise obs.LabError('preexisting_processes_refused')
  if obs.is_reparse(hosts) or hosts.stat().st_size>1024*1024:raise obs.LabError('hosts_file_refused')
  original=hosts.read_bytes()
  if contains_target(original):raise obs.LabError('preexisting_target_hosts_entry_refused')
  report['flush_before_succeeded']=flush()
  if not report['flush_before_succeeded']:raise obs.LabError('dns_flush_failed')
  pre,ips=resolve();report['resolution_before']=pre;report['target_public_addresses_before']=ips[:32]
  if pre!='public_only':raise obs.LabError('baseline_resolution_not_public')
  if mode=='block_telemetry':
   modified=original+PATCH
   hosts.write_bytes(modified);report['hosts_changed']=True
   report['flush_after_succeeded']=flush()
   if not report['flush_after_succeeded']:raise obs.LabError('post_change_flush_failed')
   state,_=resolve();report['resolution_at_launch']=state
   if state!='loopback_only':raise obs.LabError('block_effective_resolution_failed')
  else:report['resolution_at_launch']=pre
  report['launch_precondition_passed']=True;report['capture_invoked']=True
  harness.main()
  report['outcome']='collector_returned'
 except BaseException as exc:
  if isinstance(exc,(KeyboardInterrupt,GeneratorExit)):raise
  report['outcome']='stopped'
  report['error_code']=str(exc) if isinstance(exc,obs.LabError) and re.fullmatch('[a-z0-9_]{1,100}',str(exc)) else 'bounded_ab_failed'
 finally:
  if report['hosts_changed']:
   try:
    if not obs.is_reparse(hosts) and hosts.read_bytes()==modified:
     hosts.write_bytes(original);flush();report['hosts_restored']=hosts.read_bytes()==original
   except Exception:pass
  (out/'ab-intervention.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'mode':mode,'outcome':report['outcome'],'precondition':report['launch_precondition_passed']}))
if __name__=='__main__':main()
