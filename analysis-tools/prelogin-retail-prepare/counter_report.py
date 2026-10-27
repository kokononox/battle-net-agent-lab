"""Strict, source-bound non-target native counter-diagnostic receipt."""
import json
import sys
from pathlib import Path
import guard_report as g


def native(r):
    keys={'schema','source_commit','run_id','status','network_scope','boundary_kind',
          'target_launched','transfer_requested','diagnostics'}
    if type(r)is not dict or set(r)!=keys or r['schema']!='bnet-counter-native-1':
        raise ValueError('native_schema')
    g.identity(r)
    if r['status']not in {'observed','metrics_failed','counter_decreased'}:
        raise ValueError('native_status')
    if r['network_scope']!='hostwide_adapter_counters' or r['boundary_kind']!='synthetic_observation_marker':
        raise ValueError('native_scope')
    if r['target_launched']is not False or r['transfer_requested']is not False:
        raise ValueError('native_target_forbidden')
    d=g.validate_diagnostics(r['diagnostics'])
    if d['samples']>33:raise ValueError('native_samples')
    if r['status']=='observed' and (d['samples']!=33 or not d['phase_boundary_observed']):
        raise ValueError('native_incomplete')
    return r


def blank(source, run):
    return dict(schema='bnet-counter-diagnostic-run-1',source_commit=source,run_id=run,
                status='not_started',guard_build=g.blank_build(),
                portable_assertions_passed=False,native=None,target_launched=False,
                transfer_requested=False,production_limits_changed=False)


def validate(r):
    if type(r)is not dict or set(r)!=set(blank('a'*40,'1')) or r['schema']!='bnet-counter-diagnostic-run-1':
        raise ValueError('run_schema')
    g.identity(r)
    if r['status']not in {'not_started','observed','build_failed','assertions_failed','probe_failed','other'}:
        raise ValueError('run_status')
    g.validate_build(r['guard_build'])
    if type(r['portable_assertions_passed'])is not bool:raise ValueError('run_boolean')
    if any(r[k]is not False for k in ('target_launched','transfer_requested','production_limits_changed')):
        raise ValueError('run_target_forbidden')
    if r['native']is not None:
        native(r['native'])
        if any(r['native'][k]!=r[k]for k in ('source_commit','run_id')):raise ValueError('run_identity')
        if not r['portable_assertions_passed'] or r['guard_build']['stage']!='compiled':raise ValueError('run_gate')
    if r['status']=='observed' and (r['native']is None or r['native']['status']!='observed'):
        raise ValueError('run_incomplete')
    return r


if __name__=='__main__':
    r=validate(g.read(sys.argv[1]))
    if len(sys.argv)>3 and (r['source_commit']!=sys.argv[3] or r['run_id']!=sys.argv[4]):
        raise ValueError('publish_identity')
    p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(r,indent=2)+'\n')
