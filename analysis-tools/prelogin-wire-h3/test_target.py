import copy
import unittest
from test_validate import report as fixture_report
from target_validate import validate,LIMITS

def report(launched=False):
    r=dict(schema='bnet-prelogin-wire-h3-target-4',source_commit='a'*40,run_id='123',status='not_started',error_code=None,selftest=None,bootstrap_pin_match=None,target_launched=False,async_scope='event_and_registered_win32_callbacks_only',processes=[],requests=[],parse_states={},network_linked_hardware_requests=0,request_count=0,capture=None,capture_diagnostics=None,link_diagnostics=[],collector_errors=0,dropped_events=0,collector_fatal=False,limits=dict(LIMITS))
    if launched:
        f=fixture_report()
        for x in f['fixtures']:
            x.update(passed=True,stage='complete',fixture_exit_code=0,root_child_instrumented=True,bitness_confirmed=True,negative_encryption_observed=True,linked_probe_requests=2,http_responses_linked=2,completed_operations=4,witness={k:True for k in x['witness']},hook_checks={k:True for k in x['hook_checks']})
        f['passed']=True
        r.update(selftest=f,target_launched=True,bootstrap_pin_match=True,status='observation_complete')
    return r

def row():return dict(destination='telemetry-in.battle.net',method='POST',tls_record_count=1,hardware_payload_verified=True,hardware_field_count=22,cpu_reference_match=True,socket_send_linked=True,packet_bytes_linked=True,http_response_status=200,server_storage_proven=False)

def proc():return dict(name='agent.exe',sha256='a'*64,instrumented_before_resume=True,script_errors=0,pointer_bits=32,diagnostics={},observations={},completed_operations=0,unresolved_async_events=0,unlinked_immediate_events=0)

class TargetAllowlist(unittest.TestCase):
    def test_not_started(self):validate(report())
    def test_both_architectures_gate(self):validate(report(True))
    def test_no_gate_launch_refused(self):
        r=report();r['target_launched']=True
        with self.assertRaises(ValueError):validate(r)
    def test_only_one_arch_pass_refused(self):
        r=report(True);r['selftest']['fixtures'][1]['passed']=False
        with self.assertRaises(ValueError):validate(r)
    def test_stale_qualification_source_refused(self):
        r=report(True);r['selftest']['source_commit']='b'*40
        with self.assertRaises(ValueError):validate(r)
    def test_pin_mismatch_launch_refused(self):
        r=report(True);r['bootstrap_pin_match']=False
        with self.assertRaises(ValueError):validate(r)
    def test_verified_ladder(self):
        r=report(True);r.update(requests=[row()],request_count=1,network_linked_hardware_requests=1,link_diagnostics=[[dict(socket_matches=1,socket_pid_match=True,packet_matches=1,packet_prefix_matches=1,packet_suffix_matches=1)]]);validate(r)
    def test_incomplete_collector_even_nonhardware_refused(self):
        r=report(True);p=proc();p['script_errors']=1;r['processes']=[p];r['collector_errors']=1
        v=row();v.update(hardware_payload_verified=False,hardware_field_count=0,cpu_reference_match=False);r.update(requests=[v],request_count=1)
        with self.assertRaises(ValueError):validate(r)
    def test_diag_exact_allowlist(self):
        r=report(True);p=proc();p.update(script_errors=1,diagnostics={'WSARecv|enter|overlapped_reuse':1});r.update(processes=[p],collector_errors=1);validate(r)
    def test_raw_diag_refused(self):
        r=report(True);p=proc();p['diagnostics']={'PRIVATE|SECRET|ADDRESS':1};r['processes']=[p]
        with self.assertRaises(ValueError):validate(r)
    def test_unsupported_bitness_refused(self):
        r=report(True);p=proc();p['pointer_bits']=True;r['processes']=[p]
        with self.assertRaises(ValueError):validate(r)
    def test_error_crossfoot_refused(self):
        r=report();r['collector_errors']=1
        with self.assertRaises(ValueError):validate(r)
    def test_storage_claim_refused(self):
        r=report(True);v=row();v['server_storage_proven']=True;r.update(requests=[v],request_count=1,network_linked_hardware_requests=1,link_diagnostics=[[dict(socket_matches=1,socket_pid_match=True,packet_matches=1,packet_prefix_matches=1,packet_suffix_matches=1)]])
        with self.assertRaises(ValueError):validate(r)
    def test_diagnostic_alignment_required(self):
        r=report(True);r.update(requests=[row()],request_count=1,network_linked_hardware_requests=1)
        with self.assertRaises(ValueError):validate(r)
    def test_diagnostic_raw_key_rejected(self):
        r=report();r['capture_diagnostics']={'private_bytes':'SECRET'}
        with self.assertRaises(ValueError):validate(r)
    def test_capture_sizes_validated(self):
        r=report();r['capture_diagnostics']=dict(etl_bytes=67108864,pcap_bytes=1000,etl_at_configured_capacity=True);validate(r)
        r['capture_diagnostics']['etl_at_configured_capacity']=False
        with self.assertRaises(ValueError):validate(r)
    def test_partial_match_not_valid_full_evidence(self):
        r=report(True);r.update(requests=[row()],request_count=1,network_linked_hardware_requests=1,link_diagnostics=[[dict(socket_matches=1,socket_pid_match=True,packet_matches=0,packet_prefix_matches=1,packet_suffix_matches=1)]])
        with self.assertRaises(ValueError):validate(r)
    def test_boolean_match_count_rejected(self):
        r=report(True);r.update(requests=[row()],request_count=1,network_linked_hardware_requests=1,link_diagnostics=[[dict(socket_matches=True,socket_pid_match=True,packet_matches=1,packet_prefix_matches=1,packet_suffix_matches=1)]])
        with self.assertRaises(ValueError):validate(r)
    def test_counter_no_private_key(self):
        r=report(True);p=proc();p['observations']={'UUID|SECRET|ADDRESS':1};r['processes']=[p]
        with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
