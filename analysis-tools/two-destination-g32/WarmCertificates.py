"""Trusted native online validation before isolation; no installer/application requests."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1])
r={'schema':'certificate_preparation_g32_v1','requested':True,'phase':'before_isolation_before_setup','scope':'runner_current_user','all_service_accounts_prepared':False,'cold_cache_claimed':False,'cache_cleared':False,'trust_store_changed':False,'application_request_sent':False,'exact_network_fetches_audited':False,'status':'not_verified'}
def cache_snapshot():
 p=Path(os.environ['USERPROFILE'])/'AppData/LocalLow/Microsoft/CryptnetUrlCache'
 result={};total=0
 for sub in ('Content','MetaData'):
  q=p/sub
  if not q.exists():continue
  for f in list(q.iterdir())[:512]:
   if not f.is_file() or f.is_symlink():continue
   size=f.stat().st_size
   if size>8*1024*1024 or total+size>16*1024*1024:continue
   result[sub+'/'+f.name]=hashlib.sha256(f.read_bytes()).hexdigest();total+=size
 return result
try:
 if os.environ.get('BNET_ONLINE_G32')!='lab: approved ambient no Setup control G32 20261025' or (root/'before.wfw').exists():raise ValueError('preparation_phase_refused')
 before=cache_snapshot()
 exe=Path(os.environ['RUNNER_TEMP'])/'bnet-g32-bin/CertificatePrep.exe'
 with open(os.devnull,'wb') as sink:
  p=subprocess.run([str(exe),str(root)],stdout=sink,stderr=sink,timeout=60)
 native=json.loads((root/'certificate-preparation-native.json').read_text(encoding='utf-8-sig'))
 after=cache_snapshot()
 r['cache_observation']={'bounded_file_counts_before':len(before),'bounded_file_counts_after':len(after),'new_files':len(set(after)-set(before)),'changed_files':sum(before[k]!=after[k] for k in before.keys()&after.keys()),'cache_writes_are_not_proof_of_network_fetch':True}
 keys='schema host client revocation_check_requested cache_warming_requested cache_cleared preexisting_cache_state callback_observed callback_accepted certificate_present ssl_policy_errors chain_revocation_mode chain_element_count chain_statuses tls_authenticated application_request_sent status exception_codes elapsed_ms leaf_certificate_sha256 tls_protocol advertised_ca_hosts_not_fetch_log'.split()
 r['native']={k:native[k] for k in keys if k in native}
 good=p.returncode==0 and native.get('tls_authenticated') is True and native.get('callback_accepted') is True and native.get('revocation_check_requested') is True and native.get('chain_revocation_mode')=='Online' and native.get('ssl_policy_errors')==0 and native.get('chain_statuses')==[] and native.get('application_request_sent') is False
 if not good:raise ValueError('online_chain_preparation_failed')
 r['status']='online_chain_validated_before_isolation'
except Exception as e:
 r['error_code']=str(e) if type(e)==ValueError and re.fullmatch('[a-z_]{1,80}',str(e)) else 'certificate_preparation_operation_failed'
(root/'certificate-preparation.json').write_text(json.dumps(r))
print('G32_CERTIFICATE_PREPARATION '+json.dumps({'status':r['status'],'error_code':r.get('error_code')}))
if r.get('error_code'):raise SystemExit(1)
