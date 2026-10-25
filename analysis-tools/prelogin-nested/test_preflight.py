import copy,json,unittest
from preflight import blank,validate,LINUX,WINDOWS

def report(platform='linux'):
 r=blank('a'*40,'123',platform,'runner');r['facts']={k:False for k in (LINUX if platform=='linux' else WINDOWS)};r['facts']['diagnostic']='none'
 if platform=='linux':r['facts']['kvm_api_version']=None;r['status']='kvm_not_verified'
 else:r['status']='hyperv_not_verified'
 return r
class Tests(unittest.TestCase):
 def test_linux_negative(self):validate(report())
 def test_windows_negative(self):validate(report('windows'))
 def test_empty_vm_positive_not_boot(self):
  r=report();r['facts'].update(kvm_device_present=True,kvm_open_succeeded=True,kvm_api_version=12,kvm_user_memory_capable=True,kvm_vm_created=True);r['status']='kvm_vm_creation_verified_not_guest_boot';validate(r);self.assertFalse(r['limits']['guest_os_booted'])
 def test_fake_vm_rejected(self):
  r=report();r['facts']['kvm_vm_created']=True;self.assertRaises(ValueError,validate,r)
 def test_no_boot_claim(self):
  r=report();r['limits']['guest_os_booted']=True;self.assertRaises(ValueError,validate,r)
 def test_no_reboot_claim(self):
  r=report();r['limits']['host_rebooted']=True;self.assertRaises(ValueError,validate,r)
 def test_no_permissions_change(self):
  r=report();r['limits']['device_permissions_changed']=True;self.assertRaises(ValueError,validate,r)
 def test_no_raw_error(self):
  r=report();r['facts']['diagnostic']='private-path-error';self.assertRaises(ValueError,validate,r)
 def test_no_hostname(self):
  r=report();r['hostname']='secret';self.assertRaises(ValueError,validate,r)
 def test_no_cpu_model(self):
  r=report();r['facts']['cpu_model']='secret';self.assertRaises(ValueError,validate,r)
 def test_zero_boolean_rejected(self):
  r=report();r['facts']['kvm_device_present']=0;self.assertRaises(ValueError,validate,r)
 def test_unknown_boolean_allowed(self):
  r=report();r['facts']['cpu_virtualization_flag']=None;validate(r)
 def test_malformed_source(self):
  r=report();r['source_commit']='bad';self.assertRaises(ValueError,validate,r)
 def test_platform_status_mismatch(self):
  r=report();r['status']='vm_definition_created_not_guest_boot';self.assertRaises(ValueError,validate,r)
 def test_negative_resource(self):
  r=report();r['resources']['disk_free_gib']=-1;self.assertRaises(ValueError,validate,r)
 def test_windows_definition_requires_service(self):
  r=report('windows');r['facts']['vm_definition_created']=True;self.assertRaises(ValueError,validate,r)
 def test_windows_cleanup_not_independent(self):
  r=report('windows');r['facts']['vm_definition_removed']=True;self.assertRaises(ValueError,validate,r)
 def test_windows_definition_not_guest_boot(self):
  r=report('windows');r['facts'].update(hyperv_feature_installed=True,new_vm_command=True,vmms_present=True,vmms_running=True,vm_definition_created=True,vm_definition_removed=True);r['status']='vm_definition_created_not_guest_boot';validate(r)
if __name__=='__main__':unittest.main()
