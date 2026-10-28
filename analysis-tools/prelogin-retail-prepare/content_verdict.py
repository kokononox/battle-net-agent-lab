"""Offline reconciliation for an explicitly approved T9 observation.
No absence claim from a killed worker, no reuse of historical 'latest' receipts.
"""
import json,sys,hashlib
from pathlib import Path
import guard_report,transfer_probe,content_probe,operation_state

def assess(source,run,guard,transfer=None,content=None,operation=None):
 guard_report.validate(guard)
 for r,validator in ((guard,guard_report.validate),(transfer,transfer_probe.validate),(content,content_probe.validate),(operation,operation_state.validate)):
  if r is None:continue
  if r.get('source_commit')!=source or r.get('run_id')!=run:raise ValueError('stale_receipt')
  validator(r)
 o=guard['observation']
 if o is None:raise ValueError('target_not_observed')
 if o.get('budget_profile')!='approved-2g-512m-t9':raise ValueError('wrong_budget_profile')
 positive=content is not None and content['game_component_materialized']
 return dict(schema='bnet-retail-content-verdict-1',source_commit=source,run_id=run,status='official_component_materialized'if positive else'stopped_before_content_proof'if o['status']in {'network_limit','phase_network_limit','time_limit','phase_time_limit','disk_limit'}else'content_not_proven',
  supervisor_status=o['status'],job_drained=o['job_drained'],network_scope=o['network_scope'],network_threshold_bytes=o['network_threshold_bytes'],phase_network_threshold_bytes=o['phase_network_threshold_bytes'],time_limit_ms=o['time_limit_ms'],phase_time_limit_ms=o['phase_time_limit_ms'],disk_reserve_bytes=o['disk_reserve_bytes'],network_delta_bytes=o['network_delta_bytes'],phase_network_delta_bytes=o['phase_network_delta_bytes'],phase_elapsed_ms=o['phase_elapsed_ms'],hard_network_byte_cap=False,
  finalization_http_status=transfer['finalization_http_status']if transfer else None,start_http_status=transfer['start_http_status']if transfer else None,start_attempted=transfer['start_attempted']if transfer else False,post_start_queries_completed=transfer['polls']if transfer else 0,
  content_receipt_present=content is not None,content_hash_checks=content['hash_checks']if content else 0,official_component_materialized=positive,
  verified_components=[k for k,v in content['components'].items()if v['state']=='content_verified']if content else[],operation_states=len(operation['states'])if operation else 0,
  same_file_socket_delivery_proven=False,complete_game_installation_proven=False,hardware_upload_in_game_transfer_proven=False,server_storage_proven=False,downloaded_copy_downloader_identity_proven=False,game_file_absence_after_stop_proven=False)

if __name__=='__main__':
 folder=Path(sys.argv[1]);identity=json.loads((folder/'identity.json').read_text());source=identity['source_commit'];run=identity['run_id'];inputs={}
 for label in ('guard','transfer','content','operation'):
  p=folder/(label+'.json');inputs[label]=guard_report.read(p)if p.exists()else None
 r=assess(source,run,**inputs);r['evidence']=identity
 r['input_sha256']={k:hashlib.sha256((folder/(k+'.json')).read_bytes()).hexdigest()for k in inputs if inputs[k]is not None}
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
