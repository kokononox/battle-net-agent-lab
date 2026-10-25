import copy,json,unittest,xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock
import guest_boot as g
class Tests(unittest.TestCase):
 def ready(self):
  r=g.blank('a'*40,'1');r.update(status='owned_windows_reboot_verified',stage='completed',official_media_pinned=True,kvm_enabled=True,first_signal=True,second_signal=True,full_windows_boot_verified=True,same_guest_reboot_verified=True,same_profile_verified=True,dpapi_roundtrip_verified=True,owned_marker_preserved=True,serial_challenge_verified=True);return r
 def wire(self):return dict(schema='owned-guest-signal-1',challenge='a'*64,phase='first',**{k:False for k in g.BOOLEANS})
 def test_blank(self):g.validate(g.blank('a'*40,'1'))
 def test_ready(self):g.validate(self.ready())
 def test_not_real_uuid_control(self):
  r=self.ready();r['battle_net_uuid_reboot_tested']=True;self.assertRaises(ValueError,g.validate,r)
 def test_no_network_claim(self):
  r=self.ready();r['network_after_reboot_verified']=True;self.assertRaises(ValueError,g.validate,r)
 def test_no_remote_access(self):
  r=self.ready();r['remote_access_enabled']=True;self.assertRaises(ValueError,g.validate,r)
 def test_no_nic(self):
  r=self.ready();r['guest_nic_present']=True;self.assertRaises(ValueError,g.validate,r)
 def test_no_raw_fields(self):
  r=self.ready();r['private']='anything';self.assertRaises(ValueError,g.validate,r)
 def test_no_disk_export(self):
  r=self.ready();r['private_disks_exported']=True;self.assertRaises(ValueError,g.validate,r)
 def test_no_marker_without_reboot(self):
  r=self.ready();r['second_signal']=False;self.assertRaises(ValueError,g.validate,r)
 def test_no_profile_change(self):
  r=self.ready();r['same_profile_verified']=False;self.assertRaises(ValueError,g.validate,r)
 def test_no_dpapi_failure(self):
  r=self.ready();r['dpapi_roundtrip_verified']=False;self.assertRaises(ValueError,g.validate,r)
 def test_no_nonce_failure(self):
  r=self.ready();r['serial_challenge_verified']=False;self.assertRaises(ValueError,g.validate,r)
 def test_no_guest_without_kvm(self):
  r=self.ready();r['kvm_enabled']=False;self.assertRaises(ValueError,g.validate,r)
 def test_no_pin_failure(self):
  r=self.ready();r['official_media_pinned']=False;self.assertRaises(ValueError,g.validate,r)
 def test_signal(self):self.assertIsNotNone(g.signal('LABGUEST:'+json.dumps(self.wire()),'a'*64))
 def test_wrong_challenge(self):self.assertIsNone(g.signal('LABGUEST:'+json.dumps(self.wire()),'b'*64))
 def test_extra_wire_field(self):
  r=self.wire();r['raw']='private';self.assertIsNone(g.signal('LABGUEST:'+json.dumps(r),'a'*64))
 def test_wire_not_bool(self):
  r=self.wire();r['full_windows']='true';self.assertIsNone(g.signal('LABGUEST:'+json.dumps(r),'a'*64))
 def test_large_signal(self):self.assertIsNone(g.signal('LABGUEST:'+' '*9000,'a'*64))
 def test_unknown_phase(self):
  r=self.wire();r['phase']='third';self.assertIsNone(g.signal('LABGUEST:'+json.dumps(r),'a'*64))
 def test_nonce_removed(self):self.assertNotIn('challenge',g.signal('LABGUEST:'+json.dumps(self.wire()),'a'*64))
 def test_receipt(self):self.assertEqual(g.receipt('a'*40,'1','completed','success','failure','success')['preparation'],'failure')
 def test_bad_receipt(self):self.assertRaises(ValueError,g.receipt,'a'*40,'1','private')
 def test_xml(self):
  ns={'u':'urn:schemas-microsoft-com:unattend'};xml=ET.fromstring(g.answer('DummyTestOnly&<>A9!'));self.assertEqual(xml.find('.//u:AdministratorPassword/u:Value',ns).text,'DummyTestOnly&<>A9!');self.assertEqual(xml.find('.//u:MetaData/u:Value',ns).text,'2');self.assertEqual(xml.find('.//u:InstallTo/u:PartitionID',ns).text,'3')
 def test_password_not_literal(self):self.assertNotIn('DummyTestOnly',Path(g.__file__).read_text())
 def test_no_target_in_probe(self):
  s=Path(g.__file__).with_name('probe.ps1').read_text();self.assertNotIn('Blizzard Error',s);self.assertIn('OwnedGuestControl',s)
 def test_boot_compare(self):self.assertIn('$boot -gt [DateTime]::Parse($s.captured)',Path(g.__file__).with_name('probe.ps1').read_text())
 def test_send_space_event(self):
  q=MagicMock();q.read.side_effect=[{'event':'RESET'},{'return':{}}];g.send_space(q);self.assertEqual(q.read.call_count,2)
 def test_send_space_error(self):
  q=MagicMock();q.read.return_value={'error':{}};self.assertRaises(g.media.ProbeError,g.send_space,q)
if __name__=='__main__':unittest.main()
