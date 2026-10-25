"""One publisher combines independent validated replicas; absent reports stay absent."""
import json,os
from datetime import datetime
from pathlib import Path
from model import CASE,REPLICAS
from experiment_policy import POLICIES
from validate_report import decode

def summarize(inputs,source,run):
 records={};missing=[];rejected=[]
 for replica in sorted(REPLICAS):
  raw=inputs.get(replica)
  if raw is None:missing.append(replica);continue
  try:
   r=decode(raw)
   if r['replica']!=replica or r['source_commit']!=source or r['run_id']!=run:raise ValueError('identity')
   if r['status'] not in ('stopped','bounded_install_not_verified','installed_by_defined_gate') or (r['target_launched'] and r['ended_at'] is None):raise ValueError('unfinished')
   records[replica]=r
  except (ValueError,TypeError,KeyError,UnicodeError,OverflowError):rejected.append(replica)
 windows=[(r['started_at'],r['ended_at']) for r in records.values() if r['target_launched'] and r['started_at'] and r['ended_at']]
 overlap=None
 if len(windows)==len(REPLICAS):
  parse=lambda t:datetime.strptime(t,'%Y-%m-%dT%H:%M:%SZ')
  overlap=max(0,int((min(parse(b) for a,b in windows)-max(parse(a) for a,b in windows)).total_seconds()))
 status_counts={k:sum(r['status']==k for r in records.values()) for k in ('stopped','bounded_install_not_verified','installed_by_defined_gate')}
 cohort=[]
 for r in records.values():
  candidates=[b for b in r['client_binaries'] if b['kind']=='client' and b['signature_accepted']]
  cohort.append(candidates[0]['sha256'] if len(candidates)==1 else None)
 manifest=dict(schema='bnet-minimal-install-c1-batch-1',case=CASE,source_commit=source,run_id=run,expected_replicas=sorted(REPLICAS),received_replicas=sorted(records),missing_replicas=missing,rejected_replicas=rejected,status_counts=status_counts,all_six_target_windows_overlap=overlap is not None and overlap>0,common_overlap_seconds=overlap,same_signed_client_hash_across_all_six=len(cohort)==len(REPLICAS) and None not in cohort and len(set(cohort))==1,intervention='six_case_hosts_dependency_probe',necessity_tested=False,telemetry_blocked=False,replicas=[dict(replica=k,experiment_label=r['experiment_label'],hosts=r['hosts'],intervention=r['intervention'],status=r['status'],started_at=r['started_at'],ended_at=r['ended_at'],registry_version_state=r['registry_version_state'],installation_gate=r['installation_gate'],binary_probe_counts=r['binary_probe_counts'],binary_probe_failures=r['binary_probe_failures'],snapshot_errors=r['snapshot_errors'],gui_errors=r['gui_errors'],install_checks=r['install_checks'],client_binaries=r['client_binaries'],ui_signal_seen=r['ui_signal_seen'],error_code=r['error_code']) for k,r in sorted(records.items())])
 manifest['control_gate_pass_count']=sum(r['status']=='installed_by_defined_gate' for k,r in records.items() if POLICIES[k][1] is None)
 events=[(a,1) for a,b in windows]+[(b,-1) for a,b in windows];active=peak=0
 for stamp,delta in sorted(events):active+=delta;peak=max(peak,active)
 manifest['peak_target_concurrency']=peak
 manifest['conclusion_scope']='resolver_override_pilot_not_domain_necessity_or_complete_telemetry_block_proof'
 return records,manifest

def main():
 inputs={k:(Path('sanitized')/('minimal-install-c1-'+k+'.json')).read_bytes() for k in REPLICAS if (Path('sanitized')/('minimal-install-c1-'+k+'.json')).is_file()}
 records,manifest=summarize(inputs,os.environ['EXPECTED_SOURCE'],os.environ['GITHUB_RUN_ID'])
 folder=Path('reports/minimal-install-c1');folder.mkdir(parents=True,exist_ok=True)
 # Publish only this batch, never leave a stale report that could impersonate a missing replica.
 for k in REPLICAS:
  destination=folder/(k+'.json')
  if k in records:destination.write_text(json.dumps(records[k],indent=2)+'\n',encoding='utf-8')
  elif destination.exists():destination.unlink()
 (folder/'batch.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(dict(received=manifest['received_replicas'],missing=manifest['missing_replicas'],rejected=manifest['rejected_replicas'])))
if __name__=='__main__':main()
