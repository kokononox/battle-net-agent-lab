"""Reconcile independently persisted receipts without treating an older form as current.

This module makes no network requests and never changes native stopping limits.
Persisted attempt flags are intent markers written before HTTP, not delivery proof.
"""
import json
import sys
from pathlib import Path
import ci_status
import guard_report
import report
import transfer_probe


def summarize(source, run, ci, guard=None, transfer=None, form=None):
    expected = ci_status.status(source, run, ci.get('phase'),
                                ci.get('dependencies'), ci.get('tests'),
                                ci.get('observation'), ci.get('sanitization'))
    if ci != expected:
        raise ValueError('ci_identity_mismatch')
    out = dict(schema='bnet-retail-attempt-1', source_commit=source, run_id=run,
               ci=expected, supervisor_receipt='absent', transfer_receipt='absent',
               form_receipt='absent', supervisor_status=None,
               job_drained=None, final_active_processes=None,
               transfer_status=None, finalization_intent_recorded=False,
               start_intent_recorded=False, finalization_http_status=None,
               start_http_status=None, finalization_response_bytes=0,
               download_progress_observed=False,
               request_delivery_proven=False, complete_installation_proven=False,
               hardware_upload_proven=False, network_scope='hostwide_adapter_counters',
               hard_network_byte_cap=False, status='evidence_incomplete')
    for name, value, validator in (
        ('supervisor', guard, guard_report.validate),
        ('transfer', transfer, transfer_probe.validate),
        ('form', form, report.validate),
    ):
        if value is None:
            continue
        if type(value) is not dict:
            raise ValueError('receipt_object')
        guard_report.identity(value)
        if value['source_commit'] != source or value['run_id'] != run:
            # Do not validate or consume a different run's obsolete payload/schema.
            out[name + '_receipt'] = 'stale_ignored'
            continue
        validator(value)
        out[name + '_receipt'] = 'current'
        if name == 'supervisor' and value['observation'] is not None:
            o = value['observation']
            out.update(supervisor_status=o['status'], job_drained=o['job_drained'],
                       final_active_processes=o['final_active_processes'])
        elif name == 'transfer':
            out.update(transfer_status=value['status'],
                       finalization_intent_recorded=value['finalization_attempted'],
                       start_intent_recorded=value['start_attempted'],
                       finalization_http_status=value['finalization_http_status'],
                       start_http_status=value['start_http_status'],
                       finalization_response_bytes=value['finalization_response_bytes'],
                       download_progress_observed=value['last_progress'] is not None)
    if out['supervisor_status'] in {'phase_network_limit', 'phase_time_limit',
                                   'network_limit', 'disk_limit', 'time_limit'}:
        out['status'] = 'supervisor_stopped'
    elif out['supervisor_status'] == 'worker_completed':
        out['status'] = 'worker_finished'
    elif out['supervisor_status'] == 'worker_failed':
        out['status'] = 'worker_failed'
    return out


def optional(path):
    return guard_report.read(path) if Path(path).is_file() else None


def main(args):
    if len(args) != 7:
        raise ValueError('arguments')
    source, run, ci, guard, transfer, form, dest = args
    result = summarize(source, run, guard_report.read(ci), optional(guard),
                       optional(transfer), optional(form))
    p = Path(dest)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main(sys.argv[1:])
