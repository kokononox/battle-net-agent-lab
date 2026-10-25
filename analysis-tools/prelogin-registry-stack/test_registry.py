import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from registry_events import Events,decode
from validate_registry import blank,validate,load
SYN=b'abcdefab-abcd-4abc-abcd-abcdefabcdef'
def row():return dict(pid=1,sha256='a'*64)
def event():return dict(kind='reg_value',api='RegQueryValueExW',operation='read',label='target',status=0,value_type=1,caller_rva=0x123,stack_status='captured',main_module_stack_rvas=[0x123])
class Tests(unittest.TestCase):
 def test_ascii(self):self.assertEqual(decode(SYN+b'\0'),SYN)
 def test_utf16(self):self.assertEqual(decode((SYN.decode()+'\0').encode('utf-16-le')),SYN)
 def test_non_v4_refused(self):self.assertIsNone(decode(b'abcdefab-abcd-1abc-abcd-abcdefabcdef'))
 def test_private_comparison(self):
  e=Events();e.accept(row(),event(),SYN+b'\0');r=e.summary({SYN});self.assertTrue(r['records'][0]['equals_wire_host_id']);self.assertNotIn(SYN.decode(),json.dumps(r))
 def test_case_not_normalized(self):
  e=Events();e.accept(row(),event(),SYN.upper());self.assertFalse(e.summary({SYN})['records'][0]['equals_wire_host_id'])
 def test_failed_read_not_witness(self):
  e=Events();v=event();v['status']=2;e.accept(row(),v,b'');self.assertFalse(e.summary({SYN})['records'][0]['valid_uuid'])
 def test_error_with_bytes_rejected(self):
  e=Events();v=event();v['status']=2;e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_size_only_not_value(self):
  e=Events();e.accept(row(),event(),b'');self.assertFalse(e.summary({SYN})['records'][0]['valid_uuid'])
 def test_other_registry_type_not_uuid(self):
  e=Events();v=event();v['value_type']=3;e.accept(row(),v,SYN);self.assertFalse(e.summary({SYN})['records'][0]['valid_uuid'])
 def test_unknown_field_rejected(self):
  e=Events();v=event();v['path']='secret';e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_probe_not_in_target_report(self):
  e=Events();v=event();v['label']='probe';e.accept(row(),v,SYN);self.assertEqual(e.summary({SYN})['records'],[])
 def test_empty_report_valid(self):validate(blank('a'*40,'123'))
 def test_raw_report_rejected(self):
  r=blank('a'*40,'123');r['uuid']='x';self.assertRaises(ValueError,validate,r)
 def test_partial_claim_rejected(self):
  r=blank('a'*40,'123');r['registry_read_equals_wire_host_id']=True;self.assertRaises(ValueError,validate,r)
 def test_unproven_causality_rejected(self):
  r=blank('a'*40,'123');r['limits']['provider_assignment_causality_proven']=True;self.assertRaises(ValueError,validate,r)
 def test_duplicate_json_refused(self):self.assertRaises(ValueError,load,b'{"schema":1,"schema":2}')
 def test_invalid_boolean(self):
  r=blank('a'*40,'123');r['target_launched']=0;self.assertRaises(ValueError,validate,r)
 def test_negative_status_refused(self):
  e=Events();v=event();v['status']=-1;e.accept(row(),v,b'');self.assertEqual(e.errors,1)
 def test_invalid_caller_refused(self):
  e=Events();v=event();v['caller_rva']='raw-address';e.accept(row(),v,b'');self.assertEqual(e.errors,1)
if __name__=='__main__':unittest.main()

class ClaimTests(unittest.TestCase):
 def good(self):
  from validate_registry import PIN
  r=blank('a'*40,'123');r.update(status='observation_complete',target_launched=True,lifecycle_comparison=True,registry_read_equals_wire_host_id=True,baseline_before_target=dict(status='absent',value_present=False,valid_uuid=False),baseline_after_target=dict(status='present',value_present=True,valid_uuid=True))
  for arch in ('x64','x86'):r['native_gate'].append(dict(architecture=arch,passed=True,exit_code=0,instrumented=True,bitness_confirmed=True,read_a=True,read_w=True,get_w=True,write_w=True,size_only_not_uuid=True,read_w_main_frame=True,write_w_main_frame=True,accurate_stack_captured=True,errors=0,limits=0))
  for phase in ('first','second'):r['phases'].append(dict(phase=phase,ready_processes=1,installed_apis=['RegQueryValueExW'],errors=0,limits=0,wire_linked_hardware_requests=1,all_processes_registry_ready=True,wire_collector_clean=True,records=[dict(api='RegQueryValueExW',operation='read',status=0,value_type=1,caller_rva=123,stack_status='captured',main_module_stack_rvas=[],process_sha256=PIN,valid_uuid=True,equals_wire_host_id=True)]))
  return r
 def test_good(self):validate(self.good())
 def test_missing_phase_refused(self):
  r=self.good();r['phases'].pop();self.assertRaises(ValueError,validate,r)
 def test_wrong_image_cannot_prove_read(self):
  r=self.good();r['phases'][0]['records'][0]['process_sha256']='a'*64;self.assertRaises(ValueError,validate,r)
 def test_collector_error_refuses_claim(self):
  r=self.good();r['phases'][0]['errors']=1;self.assertRaises(ValueError,validate,r)
 def test_failed_native_refuses_claim(self):
  r=self.good();r['native_gate'][0]['passed']=False;self.assertRaises(ValueError,validate,r)
 def test_write_claim_requires_write(self):
  r=self.good();r['successful_matching_write_observed']=True;self.assertRaises(ValueError,validate,r)
 def test_raw_record_refused(self):
  r=self.good();r['phases'][0]['records'][0]['raw']='x';self.assertRaises(ValueError,validate,r)
 def test_nonvalue_cannot_equal(self):
  r=self.good();r['phases'][0]['records'][0]['valid_uuid']=False;self.assertRaises(ValueError,validate,r)
 def test_api_operation_mismatch(self):
  r=self.good();r['phases'][0]['records'][0]['operation']='write';self.assertRaises(ValueError,validate,r)

class StackTests(unittest.TestCase):
 def test_exact_stack(self):
  e=Events();e.accept(row(),event(),SYN);self.assertEqual(e.summary({SYN})['records'][0]['main_module_stack_rvas'],[0x123])
 def test_no_absolute_stack_strings(self):
  e=Events();v=event();v['main_module_stack_rvas']=['0x123'];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_failed_stack_cannot_have_frames(self):
  e=Events();v=event();v['stack_status']='failed';e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_no_duplicate_frames(self):
  e=Events();v=event();v['main_module_stack_rvas']=[123,123];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_bounded_stack(self):
  e=Events();v=event();v['main_module_stack_rvas']=list(range(17));e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_stack_claim_requires_frames(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True;self.assertRaises(ValueError,validate,r)
 def test_stack_claim_both_phases(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True
  for p in r['phases']:p['records'][0]['main_module_stack_rvas']=[123]
  validate(r)
 def test_stack_not_causality(self):
  r=ClaimTests().good();r['limits']['provider_assignment_causality_proven']=True;self.assertRaises(ValueError,validate,r)

class StackTests(unittest.TestCase):
 def test_exact_stack(self):
  e=Events();e.accept(row(),event(),SYN);self.assertEqual(e.summary({SYN})['records'][0]['main_module_stack_rvas'],[0x123])
 def test_no_absolute_stack_strings(self):
  e=Events();v=event();v['main_module_stack_rvas']=['0x123'];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_failed_stack_cannot_have_frames(self):
  e=Events();v=event();v['stack_status']='failed';e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_no_duplicate_frames(self):
  e=Events();v=event();v['main_module_stack_rvas']=[123,123];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_bounded_stack(self):
  e=Events();v=event();v['main_module_stack_rvas']=list(range(17));e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_stack_claim_requires_frames(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True;self.assertRaises(ValueError,validate,r)
 def test_stack_claim_both_phases(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True
  for p in r['phases']:p['records'][0]['main_module_stack_rvas']=[123]
  validate(r)
 def test_stack_not_causality(self):
  r=ClaimTests().good();r['limits']['provider_assignment_causality_proven']=True;self.assertRaises(ValueError,validate,r)

class StackTests(unittest.TestCase):
 def test_exact_stack(self):
  e=Events();e.accept(row(),event(),SYN);self.assertEqual(e.summary({SYN})['records'][0]['main_module_stack_rvas'],[0x123])
 def test_no_absolute_stack_strings(self):
  e=Events();v=event();v['main_module_stack_rvas']=['0x123'];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_failed_stack_cannot_have_frames(self):
  e=Events();v=event();v['stack_status']='failed';e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_no_duplicate_frames(self):
  e=Events();v=event();v['main_module_stack_rvas']=[123,123];e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_bounded_stack(self):
  e=Events();v=event();v['main_module_stack_rvas']=list(range(17));e.accept(row(),v,SYN);self.assertEqual(e.errors,1)
 def test_stack_claim_requires_frames(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True;self.assertRaises(ValueError,validate,r)
 def test_stack_claim_both_phases(self):
  r=ClaimTests().good();r['matching_agent_read_stack_observed']=True
  for p in r['phases']:p['records'][0]['main_module_stack_rvas']=[123]
  validate(r)
 def test_stack_not_causality(self):
  r=ClaimTests().good();r['limits']['provider_assignment_causality_proven']=True;self.assertRaises(ValueError,validate,r)
