import unittest
from run_owned_guest import validate_raw,validate

def raw():return dict(schema='owned-kvm-guest-1',api_version=12,vm_created=True,memory_registered=True,vcpu_created=True,synthetic_marker_received=True,halt_exit_received=True,failure_stage=0,guest_os_booted=False,guest_reboot_tested=False,target_launched=False)
def report():return dict(schema='bnet-owned-kvm-result-1',source_commit='a'*40,run_id='123',binary_sha256='b'*64,status='owned_guest_executed_no_OS_boot',result=raw(),host_rebooted=False,guest_os_downloaded=False,raw_identifiers_exported=False)
class Tests(unittest.TestCase):
 def test_good_synthetic(self):validate(report())
 def test_marker_required(self):
  r=report();r['result']['synthetic_marker_received']=False;self.assertRaises(ValueError,validate,r)
 def test_halt_required(self):
  r=report();r['result']['halt_exit_received']=False;self.assertRaises(ValueError,validate,r)
 def test_error_cannot_be_success(self):
  r=report();r['result']['failure_stage']=12;self.assertRaises(ValueError,validate,r)
 def test_no_windows_claim(self):
  r=raw();r['guest_os_booted']=True;self.assertRaises(ValueError,validate_raw,r)
 def test_no_reboot_claim(self):
  r=report();r['host_rebooted']=True;self.assertRaises(ValueError,validate,r)
 def test_no_raw_export(self):
  r=raw();r['memory']='raw';self.assertRaises(ValueError,validate_raw,r)
 def test_vcpu_requires_memory(self):
  r=raw();r['memory_registered']=False;self.assertRaises(ValueError,validate_raw,r)
 def test_inconclusive_valid(self):
  r=report();r.update(status='inconclusive',result=None);validate(r)
 def test_wrong_api_not_success(self):
  r=report();r['result']['api_version']=0;self.assertRaises(ValueError,validate,r)
if __name__=='__main__':unittest.main()
