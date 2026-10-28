"""Offline evidence adjudication. Never launches Agent, makes HTTP, or raises caps.

Different runs remain distinct; counters are never subtracted across runs or
converted into a unique-game-byte claim. Frozen input hashes catch drift, not
independently prove the truth of the original Windows observations.
"""
import hashlib,json,sys
from pathlib import Path
import transfer_probe,guard_report,preproduct_control,report
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'prelogin-tcp-attribution'))
import receipt,meter_receipt
EXPECTED={
 'calibration':('f58d586acc9d0407499361ad27891d90d08743d6','40609968512'),
 't5_transfer':('b7151a66d494ddfe9ee8983079b152a24d00ddab','40613265559'),
 't6_transfer':('1b3b75ae41062e70dd6aa0c54e57bfcdaec42d02','40613881968'),
 't6_meter':('1b3b75ae41062e70dd6aa0c54e57bfcdaec42d02','40613881968'),
 't6_guard':('1b3b75ae41062e70dd6aa0c54e57bfcdaec42d02','40613881968'),
 't8_transfer':('9a88bb6dbc413fd4d57ee799de6f5745b6b171d2','40614744417'),
 't8_guard':('9a88bb6dbc413fd4d57ee799de6f5745b6b171d2','40614744417'),
 't7_runtime':('bed493d6c30fe74a9d89725145178caa7f374268','40614326257'),
 't7_calibration':('bed493d6c30fe74a9d89725145178caa7f374268','40614326257'),
 't7_control':('bed493d6c30fe74a9d89725145178caa7f374268','40614326257'),
 't7_meter':('bed493d6c30fe74a9d89725145178caa7f374268','40614326257'),
 't7_guard':('bed493d6c30fe74a9d89725145178caa7f374268','40614326257'),
}
VALIDATORS={'t8_transfer':transfer_probe.validate,'t8_guard':guard_report.validate,'calibration':receipt.validate,'t5_transfer':transfer_probe.validate,'t6_transfer':transfer_probe.validate,'t6_meter':meter_receipt.validate,'t6_guard':guard_report.validate,'t7_runtime':report.validate,'t7_calibration':receipt.validate,'t7_control':preproduct_control.validate,'t7_meter':meter_receipt.validate,'t7_guard':guard_report.validate}

def load(folder):
 folder=Path(folder);manifest=guard_report.read(folder/'manifest.json')
 if set(manifest)!=set(EXPECTED):raise ValueError('incomplete_evidence')
 out={}
 for label,(source,run)in EXPECTED.items():
  m=manifest[label]
  if set(m)!={'file','sha256','source_url','source_commit','run_id'}or m['file']!=label+'.json':raise ValueError('manifest')
  raw=(folder/m['file']).read_bytes()
  if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=m['sha256']:raise ValueError('input_changed')
  value=guard_report.read(folder/m['file'])
  if(value.get('source_commit'),value.get('run_id'))!=(source,run)or(m['source_commit'],m['run_id'])!=(source,run):raise ValueError('identity')
  VALIDATORS[label](value);out[label]=value
 return out,manifest

def assess(evidence):
 if set(evidence)!=set(EXPECTED):raise ValueError('evidence')
 for k,v in evidence.items():
  VALIDATORS[k](v)
  if(v['source_commit'],v['run_id'])!=EXPECTED[k]:raise ValueError('identity')
 c=evidence['calibration'];t5=evidence['t5_transfer'];t6=evidence['t6_transfer'];m6=evidence['t6_meter'];g6=evidence['t6_guard']['observation'];p7=evidence['t7_control'];m7=evidence['t7_meter'];g7=evidence['t7_guard']['observation']
 if c['status']!='calibrated'or evidence['t7_calibration']['status']!='calibrated':raise ValueError('calibration')
 runtime=evidence['t7_runtime']
 if runtime['status']!='preproduct_control_observed'or runtime['local_requests']!=0 or runtime['initialization_attempted']or runtime['identity_failure_state']is not None or runtime['handshake']['http_requests_attempted']!=1 or runtime['handshake']['status']!='handshake_token_observed':raise ValueError('preproduct_runtime')
 # These claims require a positive checkpoint, not mere enabling or intent.
 valid6=m6['status']in {'observing','completed','time_limit'}and m6['baseline_ready']and m6['polls']>0
 valid7=m7['status']in {'observing','completed','time_limit'}and m7['baseline_ready']and m7['polls']>0
 no_phase=t6['local_requests']==0 and not any(t6[k]for k in ('finalization_attempted','start_attempted','phase_signal_created','phase_acknowledged'))
 if g6 is None or g7 is None:raise ValueError('supervision')
 prestart=valid6 and no_phase and m6['data_bytes_in_delta']>0 and not g6['transfer_phase_signal_seen']
 preproduct=valid7 and p7['identity_verified_before']and p7['meter_started']and p7['product_api_requests']==0 and m7['data_bytes_in_delta']>0 and not g7['transfer_phase_signal_seen']
 t8=evidence['t8_transfer'];g8=evidence['t8_guard']['observation']
 if g8 is None:raise ValueError('t8_supervision')
 return dict(schema='bnet-prelogin-attribution-verdict-1',calibration_exact_loopback=True,calibration_generalizes_to_all_traffic=False,
  t5_local_update_http_response_observed=t5['start_attempted']and t5['start_http_status']==200 and t5['start_response_bytes']>0,
  t5_game_content_proven=False,t5_server_telemetry_acceptance_proven=False,
  t6_inbound_before_finalization_and_update_observed=prestart,t6_observed_tcp_in_octets=m6['data_bytes_in_delta'],t6_product_initialization_already_performed=True,t6_global_stop=g6['status'],
  t7_inbound_with_zero_harness_product_api_requests_observed=preproduct,t7_observed_tcp_in_octets=m7['data_bytes_in_delta'],t7_observed_tcp_out_octets=m7['data_bytes_out_delta'],t7_meter_window_ms=m7['elapsed_ms'],t7_product_api_requests=p7['product_api_requests'],t7_control_status=p7['status'],t7_meter_status=m7['status'],t7_supervisor_status=g7['status'],t7_control_completed=p7['status']=='observed'and m7['status']=='completed'and g7['status']=='worker_completed',
  t8_finalization_http_observed=t8['finalization_http_status']==200 and t8['finalization_response_bytes']>0,t8_start_attempted=t8['start_attempted'],t8_supervisor_status=g8['status'],t8_after_start_progress_proven=False,
  tcp_retransmissions_may_be_included=True,all_process_traffic_covered=False,counters_identify_payload_content=False,
  game_download_without_login_proven=False,hardware_upload_during_game_download_proven=False,copied_game_downloader_provenance_proven=False,server_storage_proven=False,guard_limits_changed=False,
  cross_run_counter_subtraction_used=False)

if __name__=='__main__':
 e,m=load(sys.argv[1]);r=assess(e);r['inputs']=m
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
