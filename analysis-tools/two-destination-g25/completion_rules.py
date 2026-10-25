"""Conservative completion evidence; process count never means restart count."""
def assess(processes,ui,artifacts,registry,install_clicked):
 rows=processes.get('records',[])
 mains=[x for x in rows if x.get('kind')=='client' and x.get('role')=='no_type_switch']
 survived=any(x.get('observed_lifetime_ms',0)>=60000 and x.get('alive_before_controller_termination') is True for x in mains)
 natural_root_zero=any(x.get('kind')=='setup' and x.get('exit_code')=='0x00000000' and x.get('alive_before_controller_termination') is False for x in rows)
 samples=[x for x in ui.get('samples',[]) if x.get('status')=='ok' and x.get('client_login_controls_present') is True]
 ready=len(samples)>=2 and max(x['elapsed_seconds'] for x in samples)-min(x['elapsed_seconds'] for x in samples)>=30
 signed={x.get('kind') for x in artifacts if x.get('signature_accepted') is True and x.get('pe_file') is True and x.get('sha256')}
 registered=any(x.get('display_name_matches') and x.get('install_location_matches') and x.get('uninstall_exe_present_inside_install_root') for x in registry.get('records',[]))
 complete=all([install_clicked,natural_root_zero,survived,ready,{'client','launcher'}<=signed,registered,processes.get('identity_capture_failures')==0,not ui.get('query_errors')])
 return {'schema':'conservative_completion_assessment_v1','install_action_returned':install_clicked,'setup_natural_zero_exit_observed':natural_root_zero,'client_no_type_switch_instances':len(mains),'client_typed_subprocess_instances':sum(x.get('kind')=='client' and x.get('role') not in {'no_type_switch','unavailable'} for x in rows),'process_count_does_not_prove_restarts':True,'main_process_survival_60s_observed':survived,'client_login_controls_observed_over_30s':ready,'signed_client_and_launcher_verified':{'client','launcher'}<=signed,'uninstall_registration_matches':registered,'complete_installation_verified':complete,'status':'installed_client_ready_without_login_observed' if complete else 'completion_not_verified'}
