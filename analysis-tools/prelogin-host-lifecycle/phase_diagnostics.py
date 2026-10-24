"""Fixed diagnostic labels only. Even failed child verification cannot export a path."""
STAGES={'not_started','pin','capture','spawn','observe','complete'}
ERRORS={None,'RuntimeError','OSError','ValueError','TimeoutExpired','ProcessNotFoundError','InvalidOperationError','TimedOutError','TransportError','PermissionDeniedError','LabError','other'}
NAMES={'agent.exe','battle.net.exe','battle.net launcher.exe','battle.net-setup.exe','battle.net helper.exe','blizzarderror.exe','other'}
PHASES={'verify','attach','child_gating','script_load','resume','observing','other'}
STATES={'paused','refused_or_failed','resumed','other'}
REFUSALS={None,'unexpected_image_name','reparse_or_missing_image','image_size','image_signature'}
def error_kind(name):return name if name in ERRORS else 'other'
def blank_debug():return dict(stage='not_started',error_type=None,refusal_reason=None,processes=[])
def collect_diagnostics(p,d,manager):
    rows=list(manager.rows.values())
    p.update(instrumented_processes=len(rows),all_processes_instrumented=bool(rows) and all(x['instrumented_before_resume'] for x in rows),collector_errors=sum(x['script_errors'] for x in rows),dropped_events=manager.dropped,collector_fatal=manager.fatal)
    d['processes']=[dict(name=x['process_name'] if x['process_name'] in NAMES else 'other',phase=x['phase'] if x['phase'] in PHASES else 'other',status=x['status'] if x['status'] in STATES else 'other',error_type=error_kind(x['error_kind']),instrumented_before_resume=x['instrumented_before_resume'],script_errors=x['script_errors']) for x in rows]
def validate_debug(d):
    if type(d) is not dict or set(d)!={'stage','error_type','refusal_reason','processes'}:raise ValueError('debug_schema')
    if d['stage'] not in STAGES or d['error_type'] not in ERRORS or d['refusal_reason'] not in REFUSALS:raise ValueError('debug_label')
    if type(d['processes']) is not list or len(d['processes'])>9:raise ValueError('debug_processes')
    for x in d['processes']:
        if type(x) is not dict or set(x)!={'name','phase','status','error_type','instrumented_before_resume','script_errors'}:raise ValueError('debug_process')
        if x['name'] not in NAMES or x['phase'] not in PHASES or x['status'] not in STATES or x['error_type'] not in ERRORS:raise ValueError('debug_process_label')
        if type(x['instrumented_before_resume']) is not bool or type(x['script_errors']) is not int or not 0<=x['script_errors']<=100000:raise ValueError('debug_counter')
    return d
