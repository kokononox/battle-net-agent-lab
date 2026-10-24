import copy
import unittest
from validate import validate,BOOLS,COUNTS,WITNESS,CHECKS

def report():
    rows=[]
    for arch in ('x64','x86'):
        f={k:False for k in BOOLS};f.update({k:0 for k in COUNTS})
        f.update(architecture=arch,stage='compile',error_type=None,fixture_exit_code=None,diagnostics={},observations={},capture_issues={},witness={k:False for k in WITNESS},hook_checks={k:False for k in CHECKS});rows.append(f)
    return dict(schema='bnet-h3-owned-fixtures-5',source_commit='a'*40,run_id='123',target_launched=False,game_download_requested=False,raw_values_exported=False,tls_validation_changed=False,scope='owned_loopback_and_example_com_only',async_scope='event_and_registered_win32_callbacks_only',diagnostic_counters_partial=True,iocp_supported=False,callback_supported=False,all_network_paths_covered=False,passed=False,fixtures=rows)
class Allowlist(unittest.TestCase):
    def test_failure_report_valid(self):validate(report())
    def test_raw_field_refused(self):
        r=report();r['raw']='SECRET'
        with self.assertRaises(ValueError):validate(r)
    def test_raw_nested_field_refused(self):
        r=report();r['fixtures'][0]['witness']['uuid']='SECRET'
        with self.assertRaises(ValueError):validate(r)
    def test_untrusted_error_text_refused(self):
        r=report();r['fixtures'][0]['diagnostics']={'recv|leave|PRIVATE_ADDRESS':1};r['fixtures'][0]['collector_errors']=1
        with self.assertRaises(ValueError):validate(r)
    def test_forged_overall_pass_refused(self):
        r=report();r['passed']=True
        with self.assertRaises(ValueError):validate(r)
    def test_forged_arch_pass_refused(self):
        r=report();r['fixtures'][0]['passed']=True
        with self.assertRaises(ValueError):validate(r)
    def test_product_launch_refused(self):
        r=report();r['target_launched']=True
        with self.assertRaises(ValueError):validate(r)
    def test_packet_labels_allowlisted(self):
        r=report();r['fixtures'][0]['capture_issues']={'ip_bounds':2,'tcp_overlap_conflict':1};validate(r)
    def test_private_packet_key_refused(self):
        r=report();r['fixtures'][0]['capture_issues']={'192.0.2.1':1}
        with self.assertRaises(ValueError):validate(r)
    def test_inconsistent_diagnostic_count_refused(self):
        r=report();r['fixtures'][0]['diagnostics']={'recv|leave|bounded':1}
        with self.assertRaises(ValueError):validate(r)
    def test_unsupported_scope_cannot_be_promoted(self):
        r=report();r['iocp_supported']=True
        with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
