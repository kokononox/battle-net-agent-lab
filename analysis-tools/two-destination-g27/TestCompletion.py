import copy,unittest
from completion_rules import assess
class Tests(unittest.TestCase):
 def setUp(self):
  self.p={'identity_capture_failures':0,'records':[{'kind':'setup','role':'no_type_switch','exit_code':'0x00000000','alive_before_controller_termination':False},{'kind':'client','role':'no_type_switch','observed_lifetime_ms':65000,'alive_before_controller_termination':True},{'kind':'client','role':'renderer','observed_lifetime_ms':64000,'alive_before_controller_termination':True}]}
  self.u={'query_errors':0,'samples':[{'status':'ok','client_login_controls_present':True,'elapsed_seconds':100},{'status':'ok','client_login_controls_present':True,'elapsed_seconds':135}]}
  self.a=[{'kind':x,'pe_file':True,'sha256':'a'*64,'signature_accepted':True} for x in ['client','launcher']]
  self.r={'records':[{'display_name_matches':True,'install_location_matches':True,'uninstall_exe_present_inside_install_root':True}]}
 def result(self,clicked=True):return assess(self.p,self.u,self.a,self.r,clicked)
 def test_all_required(self):self.assertTrue(self.result()['complete_installation_verified'])
 def test_processes_not_restarts(self):self.assertEqual(self.result()['client_no_type_switch_instances'],1);self.assertEqual(self.result()['client_typed_subprocess_instances'],1)
 def test_no_install_click(self):self.assertFalse(self.result(False)['complete_installation_verified'])
 def test_no_natural_setup_exit(self):self.p['records'][0]['alive_before_controller_termination']=True;self.assertFalse(self.result()['complete_installation_verified'])
 def test_setup_nonzero_exit(self):self.p['records'][0]['exit_code']='0xc0000005';self.assertFalse(self.result()['complete_installation_verified'])
 def test_no_stable_main(self):self.p['records'][1]['observed_lifetime_ms']=30000;self.assertFalse(self.result()['complete_installation_verified'])
 def test_exited_main(self):self.p['records'][1]['alive_before_controller_termination']=False;self.assertFalse(self.result()['complete_installation_verified'])
 def test_no_login_ui(self):self.u['samples']=[];self.assertFalse(self.result()['complete_installation_verified'])
 def test_single_ui_sample(self):self.u['samples']=self.u['samples'][:1];self.assertFalse(self.result()['complete_installation_verified'])
 def test_ui_short_interval(self):self.u['samples'][1]['elapsed_seconds']=110;self.assertFalse(self.result()['complete_installation_verified'])
 def test_no_trusted_client(self):self.a[0]['signature_accepted']=False;self.assertFalse(self.result()['complete_installation_verified'])
 def test_no_registry(self):self.r['records']=[];self.assertFalse(self.result()['complete_installation_verified'])
 def test_identity_uncertainty(self):self.p['identity_capture_failures']=1;self.assertFalse(self.result()['complete_installation_verified'])
 def test_ui_error(self):self.u['query_errors']=1;self.assertFalse(self.result()['complete_installation_verified'])
 def test_renderer_alone_not_main(self):self.p['records']=self.p['records'][2:];self.assertFalse(self.result()['main_process_survival_60s_observed'])
 def test_expected_programdata_uninstaller(self):
  self.r['records'][0]['uninstall_exe_present_inside_install_root']=False;self.r['records'][0]['uninstaller_present_in_expected_roots']=True;self.assertTrue(self.result()['package_installation_verified'])
 def test_package_independent_of_login(self):
  self.u['samples']=[];self.assertTrue(self.result()['package_installation_verified']);self.assertFalse(self.result()['complete_installation_verified'])
 def test_package_needs_setup_zero(self):
  self.p['records'][0]['exit_code']='0xc0000005';self.assertFalse(self.result()['package_installation_verified'])
if __name__=='__main__':unittest.main()
