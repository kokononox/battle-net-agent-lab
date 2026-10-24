import copy,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.append(str(HERE.parent/'prelogin-audit'))
from identity_compare import Tracking,compare,eligible,PINNED_AGENT
from validate_lifecycle import validate,load,LIMITS

def v(n):
    a=bytearray()
    while n>=128:a.append((n&127)|128);n>>=7
    a.append(n);return bytes(a)
def b(n,s):return v(n*8+2)+v(len(s))+s
def request(value=b'00000000-0000-4000-8000-000000000001'):
    body=b(1,b(4,b(1,value)))+b(2,b'Blizzard.Telemetry.Distribution.Agent')+b(3,b'StartAgent')+b(4,b'')
    return dict(host='telemetry-in.battle.net',method='POST',body=body,content_type='application/octet-stream')
def tracker(value=None):
    t=Tracking(lambda r,s:dict(hardware_payload_verified=True))
    t(request() if value is None else request(value),PINNED_AGENT);return t
def phase():
    return dict(launched=True,completed=True,bootstrap_pin_match=True,instrumented_processes=3,collector_errors=0,dropped_events=0,collector_fatal=False,request_count=18,hardware_requests=1,wire_linked_hardware_requests=1,host_id_observations=1,host_id_unique=1,invalid_host_id_events=0,all_processes_instrumented=True,language_status='not_observed')
def report():
    return dict(schema='bnet-host-lifecycle-2',source_commit='a'*40,run_id='123',status='same_host_id_after_process_restart',error_code=None,first_native_gate_passed=True,same_machine=True,configuration_preserved=True,second_start_clean_processes=True,comparison=True,phases=[phase(),phase()],second_diagnostics=dict(stage='complete',error_type=None,refusal_reason=None,processes=[dict(name='agent.exe',phase='observing',status='resumed',error_type=None,instrumented_before_resume=True,script_errors=0) for _ in range(3)]),limits=dict(LIMITS))
class Tests(unittest.TestCase):
    def test_same(self):self.assertIs(compare(tracker(),tracker(),[phase(),phase()]),True)
    def test_different(self):self.assertIs(compare(tracker(),tracker(b'00000000-0000-4000-8000-000000000002'),[phase(),phase()]),False)
    def test_no_hwid_guess(self):
        t=tracker(b'computer-name');self.assertEqual(t.summary(),dict(host_id_observations=0,host_id_unique=0,invalid_host_id_events=1))
    def test_uppercase_uuid4_accepted(self):
        t=tracker(b'ABCDEFAB-ABCD-4ABC-ABCD-ABCDEFABCDEF');self.assertEqual(t.observations,1);self.assertEqual(t.invalid,0)
    def test_case_not_silently_normalized(self):
        a=tracker(b'ABCDEFAB-ABCD-4ABC-ABCD-ABCDEFABCDEF');b=tracker(b'abcdefab-abcd-4abc-abcd-abcdefabcdef');self.assertIs(compare(a,b,[phase(),phase()]),False)
    def test_non_v4_refused(self):self.assertEqual(tracker(b'00000000-0000-1000-8000-000000000001').invalid,1)
    def test_duplicate_slot_refused(self):
        r=request();r['body']=b(1,b(4,b(1,b'x')+b(1,b'y')))+b(2,b'Blizzard.Telemetry.Distribution.Agent')+b(3,b'StartAgent')
        t=Tracking(lambda r,s:dict(hardware_payload_verified=True));t(r,PINNED_AGENT);self.assertEqual(t.invalid,1)
    def test_wrong_image_not_named(self):
        t=Tracking(lambda r,s:dict(hardware_payload_verified=True));t(request(),'b'*64);self.assertEqual(t.observations,0)
    def test_wrong_destination_not_named(self):
        t=Tracking(lambda r,s:dict(hardware_payload_verified=True));r=request();r['host']='other';t(r,PINNED_AGENT);self.assertEqual(t.observations,0)
    def test_non_hardware_not_named(self):
        t=Tracking(lambda r,s:dict(hardware_payload_verified=False));t(request(),PINNED_AGENT);self.assertEqual(t.observations,0)
    def test_unobserved_not_equal(self):
        t=Tracking(lambda r,s:dict(hardware_payload_verified=True));self.assertIsNone(compare(t,t,[phase(),phase()]))
    def test_ambiguous_refused(self):
        t=tracker();t(request(b'00000000-0000-4000-8000-000000000002'),PINNED_AGENT);self.assertIsNone(compare(t,tracker(),[phase(),phase()]))
    def test_incomplete_refused(self):
        for key,val in [('completed',False),('collector_errors',1),('dropped_events',1),('collector_fatal',True),('all_processes_instrumented',False),('host_id_unique',2),('invalid_host_id_events',1)]:
            p=phase();p[key]=val;self.assertFalse(eligible(p));self.assertIsNone(compare(tracker(),tracker(),[phase(),p]))
    def test_valid(self):validate(report());load(json.dumps(report()).encode())
    def test_false_verdict(self):
        r=report();r.update(comparison=False,status='changed_host_id_after_process_restart');validate(r)
    def test_raw_extra_rejected(self):
        for key in ('host_id','uuid','source_id','hash','raw','path'):
            r=report();r[key]='synthetic';self.assertRaises(ValueError,validate,r)
    def test_nested_extra_rejected(self):
        r=report();r['phases'][0]['host_id']='synthetic';self.assertRaises(ValueError,validate,r)
    def test_zero_as_boolean_rejected(self):
        r=report();r['comparison']=0;self.assertRaises(ValueError,validate,r)
    def test_gate_required(self):
        for k in ('first_native_gate_passed','same_machine','configuration_preserved','second_start_clean_processes'):
            r=report();r[k]=False;self.assertRaises(ValueError,validate,r)
    def test_no_wire_on_drop(self):
        r=report();r['phases'][0]['dropped_events']=1;self.assertRaises(ValueError,validate,r)
    def test_mismatched_verdict_rejected(self):
        r=report();r['comparison']=False;self.assertRaises(ValueError,validate,r)
    def test_no_reboot_claim(self):
        r=report();r['limits']['reboot_tested']=True;self.assertRaises(ValueError,validate,r)
    def test_duplicate_json_rejected(self):self.assertRaises(ValueError,load,b'{"schema":1,"schema":2}')
    def test_summary_never_values(self):
        t=tracker();s=json.dumps(t.summary());self.assertNotIn('00000000-',s);self.assertEqual(set(t.summary()),{'host_id_observations','host_id_unique','invalid_host_id_events'})
    def test_stopped_valid(self):
        r=report();r.update(status='stopped',comparison=None,error_code='bounded_lifecycle_failed');r['phases']=[];r['second_diagnostics']['processes']=[];validate(r)
class DiagnosticTests(unittest.TestCase):
    def test_failed_process_count_retained(self):
        from phase_diagnostics import blank_debug,collect_diagnostics,validate_debug
        class M:pass
        m=M();m.rows={1:dict(process_name=None,phase='verify',status='refused_or_failed',error_kind='UnknownPrivateException',instrumented_before_resume=False,script_errors=2)};m.dropped=0;m.fatal=True
        p=phase();d=blank_debug();collect_diagnostics(p,d,m);validate_debug(d)
        self.assertEqual(p['collector_errors'],2);self.assertTrue(p['collector_fatal']);self.assertFalse(p['all_processes_instrumented']);self.assertEqual(d['processes'][0]['name'],'other');self.assertEqual(d['processes'][0]['error_type'],'other')
    def test_raw_debug_label_rejected(self):
        from phase_diagnostics import blank_debug,validate_debug
        d=blank_debug();d['error_type']='private-path';self.assertRaises(ValueError,validate_debug,d)
    def test_comparison_needs_complete_diagnostics(self):
        r=report();r['second_diagnostics']['stage']='observe';self.assertRaises(ValueError,validate,r)
    def test_debug_extra_rejected(self):
        r=report();r['second_diagnostics']['raw']='secret';self.assertRaises(ValueError,validate,r)
if __name__=='__main__':unittest.main()
