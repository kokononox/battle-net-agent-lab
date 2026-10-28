"""Source-bound offline reconciliation. Public format claims are not observations."""
import hashlib,json,sys
from pathlib import Path
import guard_report as g,poststop_content as p,operation_state,transfer_probe

def assess(source,run,guard,poststop=None,operation=None,transfer=None):
 for value,validator in ((guard,g.validate),(poststop,p.validate),(operation,operation_state.validate),(transfer,transfer_probe.validate)):
  if value is None:continue
  validator(value)
  if value['source_commit']!=source or value['run_id']!=run:raise ValueError('stale_receipt')
 o=guard['observation']
 if o is None or o.get('budget_profile')!='approved-2g-512m-t9':raise ValueError('budget')
 if poststop is not None and(not o['job_drained']or o['final_active_processes']!=0):raise ValueError('not_drained')
 pm=poststop.get('prefix_marker',{})if poststop else {};hm=poststop.get('host_marker',{})if poststop else {}
 confirmed=[s for s in operation['states']if s['resource']=='update'and s['post_response_identity_verified']]if operation else []
 return dict(source_commit=source,run_id=run,supervisor_status=o['status'],job_drained=o['job_drained'],network_threshold_bytes=o['network_threshold_bytes'],phase_network_threshold_bytes=o['phase_network_threshold_bytes'],time_limit_ms=o['time_limit_ms'],phase_time_limit_ms=o['phase_time_limit_ms'],disk_reserve_bytes=o['disk_reserve_bytes'],network_scope=o['network_scope'],network_delta_bytes=o['network_delta_bytes'],phase_network_delta_bytes=o['phase_network_delta_bytes'],phase_elapsed_ms=o['phase_elapsed_ms'],hard_network_byte_cap=False,
  start_http_status=transfer['start_http_status']if transfer else None,post_start_identity_verified_checkpoints=len(confirmed),offline_status=poststop['status']if poststop else None,official_build_config_materialized=bool(poststop and poststop['objects']['build_config']),official_component_materialized=bool(poststop and poststop['official_component_materialized']),host_related_container_marker_observed=bool(hm.get('host_related_container_marker_observed')or pm.get('host_related_container_marker_observed')),owned_file_prefixes_checked=pm.get('file_prefixes_checked',0),prefix_candidates_checked=pm.get('candidate_blocks_checked',0),unsupported_index_files=poststop.get('index_layout_states',{}).get('unsupported_layout')if poststop else None,
  file_absence_proven=False,same_file_socket_delivery_proven=False,hardware_upload_during_same_game_operation_proven=False,downloader_person_identity_proven=False,complete_game_installation_proven=False)

def collect(folders):
 runs=[]
 for folder in folders:
  folder=Path(folder);identity=g.read(folder/'identity.json');source=identity['source_commit'];run=identity['run_id'];values={};hashes={}
  for label in ('guard','poststop','operation','transfer'):
   path=folder/(label+'.json');values[label]=g.read(path)if path.exists()else None
   if path.exists():hashes[label]=hashlib.sha256(path.read_bytes()).hexdigest()
  row=assess(source,run,**values);row['evidence']=identity;row['input_sha256']=hashes;runs.append(row)
 return dict(schema='bnet-retail-research-t10-t13-1',runs=runs,official_build_config_positive_runs=sum(r['official_build_config_materialized']for r in runs),official_component_positive_runs=sum(r['official_component_materialized']for r in runs),host_related_container_marker_positive_runs=sum(r['host_related_container_marker_observed']for r in runs),format_hypothesis_source='https://wowdev.wiki/CASC#Data_Files',format_description_is_not_live_evidence=True,hostname_marker_absence_in_complete_installation_proven=False,hardware_upload_during_same_game_operation_proven=False,server_storage_proven=False,downloader_person_identity_proven=False,network_budget_increased=False,account_login_performed=False,game_executed=False,next_useful_input='existing_real_CASC_archive_locally_checked_without_identifier_export')
if __name__=='__main__':
 r=collect(sys.argv[1:-1]);Path(sys.argv[-1]).write_text(json.dumps(r,indent=2)+'\n')
