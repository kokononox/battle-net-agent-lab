"""Offline, source-bound negative-control verdict. No target or network operations."""
import json
import sys
from pathlib import Path
import guard_report
import transfer_probe


def summarize(guard, transfer):
    guard_report.validate(guard)
    transfer_probe.validate(transfer)
    if any(guard[k] != transfer[k] for k in ('source_commit', 'run_id')):
        raise ValueError('control_identity')
    o = guard['observation']
    if o is None or o.get('phase_arming_acknowledged') is not True:
        raise ValueError('control_not_armed')
    if (transfer['status'] != 'identity_control_observed'
            or transfer['finalization_attempted'] or transfer['start_attempted']
            or transfer['local_requests'] != 0 or transfer['polls'] != 0
            or transfer.get('phase_acknowledged') is not True
            or not o['job_drained'] or o['final_active_processes'] != 0):
        raise ValueError('control_evidence')
    if (o['status'] != 'phase_network_limit'
            or o['phase_network_delta_bytes'] < o['phase_network_threshold_bytes']):
        raise ValueError('control_no_limit_event')
    return dict(schema='bnet-retail-negative-control-1',
                source_commit=guard['source_commit'], run_id=guard['run_id'],
                phase_http_requests=0, finalization_requested=False,
                update_requested=False,
                phase_network_delta_bytes=o['phase_network_delta_bytes'],
                phase_elapsed_ms=o['phase_elapsed_ms'],
                phase_limit_without_phase_http_observed=True,
                destination_empty_at_last_snapshot=(transfer['last_files'] ==
                    dict(files=0, directories=0, bytes=0)),
                network_scope='hostwide_adapter_counters',
                traffic_process_attributed=False, counter_bug_proven=False,
                automatic_agent_activity_excluded=False,
                all_game_download_excluded=False,
                complete_installation_proven=False,
                hardware_upload_in_download_phase_proven=False,
                job_drained=True)


if __name__ == '__main__':
    g, t, dest = sys.argv[1:]
    out = summarize(guard_report.read(g), guard_report.read(t))
    Path(dest).write_text(json.dumps(out, indent=2) + '\n')
