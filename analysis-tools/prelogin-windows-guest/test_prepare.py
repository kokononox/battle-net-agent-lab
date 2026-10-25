import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
from prepare_guest import blank,validate,ISO_URL,ISO_BYTES,MIN_FREE,CLEANUP,safe_cleanup_path,image_metadata,ProbeError

def image(index=2,edition='ServerStandardEval',installation='Server'):
 return f'<IMAGE INDEX="{index}"><WINDOWS><ARCH>9</ARCH><EDITIONID>{edition}</EDITIONID><INSTALLATIONTYPE>{installation}</INSTALLATIONTYPE><VERSION><BUILD>26100</BUILD></VERSION></WINDOWS></IMAGE>'
def xml():return ('<WIM>'+image(1,installation='Server Core')+image()+image(3,edition='ServerDatacenterEval',installation='Server Core')+image(4,edition='ServerDatacenterEval')+'</WIM>').encode()
def ready():
 r=blank('a'*40,'123');r.update(status='prepared_paused_no_windows_boot',apt_tools_installed=True,qemu_version='8.2.2',disk_free_after_cleanup_bytes=MIN_FREE)
 images,index=image_metadata(xml());r['image'].update(downloaded_bytes=ISO_BYTES,sha256='b'*64,download_complete=True,images=images,selected_index=index);r['disk'].update(created=True,actual_bytes=196608);r['qemu']={k:True for k in r['qemu']};return r
class Tests(unittest.TestCase):
 def test_blank(self):validate(blank('a'*40,'123'))
 def test_ready(self):validate(ready())
 def test_image_selection(self):
  images,index=image_metadata(xml());self.assertEqual(index,2);self.assertEqual(len(images),4)
 def test_utf16(self):self.assertEqual(image_metadata(xml().decode().encode('utf-16'))[1],2)
 def test_ambiguous_image(self):self.assertRaises(ProbeError,image_metadata,('<WIM>'+image()+image(5)+'</WIM>').encode())
 def test_duplicate_index(self):self.assertRaises(ProbeError,image_metadata,('<WIM>'+image()+image()+'</WIM>').encode())
 def test_core_not_desktop(self):self.assertRaises(ProbeError,image_metadata,('<WIM>'+image(1,installation='Server Core')+'</WIM>').encode())
 def test_unknown_edition(self):self.assertRaises(ProbeError,image_metadata,('<WIM>'+image(edition='Other')+'</WIM>').encode())
 def test_no_doctype_utf8(self):self.assertRaises(ProbeError,image_metadata,b'<!DOCTYPE WIM><WIM/>')
 def test_no_doctype_utf16(self):self.assertRaises(ProbeError,image_metadata,'<!DOCTYPE WIM><WIM/>'.encode('utf-16'))
 def test_large_xml(self):self.assertRaises(ProbeError,image_metadata,b'X'*1048577)
 def test_cleanup_wrong_label(self):self.assertFalse(safe_cleanup_path('other',Path('/usr/local/lib/android'),Path('/repo')))
 def test_cleanup_not_arbitrary(self):self.assertFalse(safe_cleanup_path('android',Path('/home/runner'),Path('/repo')))
 def test_cleanup_no_symlink(self):
  with patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_symlink',return_value=True):self.assertFalse(safe_cleanup_path('android',CLEANUP['android'],Path('/repo')))
 def test_cleanup_no_workspace_ancestor(self):
  with patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'resolve',lambda p:p):self.assertFalse(safe_cleanup_path('android',CLEANUP['android'],Path('/usr/local/lib/android/repo')))
 def test_cleanup_no_workspace_equal(self):
  with patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'resolve',lambda p:p):self.assertFalse(safe_cleanup_path('android',CLEANUP['android'],CLEANUP['android']))
 def test_cleanup_fixed_ok(self):
  with patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'resolve',lambda p:p):self.assertTrue(safe_cleanup_path('android',CLEANUP['android'],Path('/repo')))
 def test_no_arbitrary_error(self):
  r=ready();r['error_code']='raw path';self.assertRaises(ValueError,validate,r)
 def test_no_private_fields(self):
  r=ready();r['path']='secret';self.assertRaises(ValueError,validate,r)
 def test_no_windows_boot_claim(self):
  r=ready();r['limits']['windows_guest_booted']=True;self.assertRaises(ValueError,validate,r)
 def test_no_reboot_claim(self):
  r=ready();r['limits']['host_rebooted']=True;self.assertRaises(ValueError,validate,r)
 def test_no_target_claim(self):
  r=ready();r['limits']['target_launched']=True;self.assertRaises(ValueError,validate,r)
 def test_exact_microsoft_url(self):
  r=ready();r['image']['url']='https://example.com/image.iso';self.assertRaises(ValueError,validate,r)
 def test_complete_download_size_required(self):
  r=ready();r['image']['downloaded_bytes']=1;self.assertRaises(ValueError,validate,r)
 def test_complete_download_hash_required(self):
  r=ready();r['image']['sha256']=None;self.assertRaises(ValueError,validate,r)
 def test_kvm_required(self):
  r=ready();r['qemu']['kvm_enabled']=False;self.assertRaises(ValueError,validate,r)
 def test_no_unselected_image(self):
  r=ready();r['image']['selected_index']=1;self.assertRaises(ValueError,validate,r)
 def test_preparation_budget(self):
  self.assertEqual(MIN_FREE,32*1024**3)
  self.assertGreater(MIN_FREE,3*ISO_BYTES)
 def test_below_capacity_boundary(self):
  r=ready();r['disk_free_after_cleanup_bytes']=MIN_FREE-1;self.assertRaises(ValueError,validate,r)
 def test_cleanup_headroom_required(self):
  r=ready();r['disk_free_after_cleanup_bytes']=1;self.assertRaises(ValueError,validate,r)
 def test_no_actual_state_artifacts(self):
  r=ready();r['limits']['private_logs_or_disks_exported']=True;self.assertRaises(ValueError,validate,r)
 def test_no_permanent_disk_claim(self):
  r=ready();r['disk']['temporary_only']=False;self.assertRaises(ValueError,validate,r)
if __name__=='__main__':unittest.main()
