from pathlib import Path
import copy,sys,unittest
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lab'))
from console import request_for
from policy import new_config,program_id,blacklist_entry,PolicyError
class LabTests(unittest.TestCase):
    def setUp(self):
        c=new_config();self.path=r'C:\Example\Game.exe';pid=program_id(self.path)
        c['programs']=[dict(id=pid,path=self.path,sha256='a'*64,enabled=True)]
        c['blacklist']=[blacklist_entry([pid],'8.8.8.8','TCP',443)]
        self.state=dict(owner='b'*32,config=c);self.store=Mock();self.store.read.return_value=self.state;self.store.verified_programs.return_value=(self.state,c['programs'])
    def test_blacklist_scope(self):
        r=request_for(self.store);self.assertEqual(len(r['plan']['rules']),1);self.assertEqual(r['plan']['rules'][0]['spec']['program'],self.path);self.store.verified_programs.assert_called_once()
    def test_full_isolation_refused_before_verification(self):
        self.state['config'].update(mode='full_isolation',whitelist=['8.8.8.8'])
        with self.assertRaisesRegex(PolicyError,'not_implemented'):request_for(self.store)
        self.store.verified_programs.assert_not_called()
    def test_legacy_import_refused(self):
        self.state['config']['legacy_imports']=[dict(kind='blacklist',rules_may_still_be_active=True)]
        with self.assertRaisesRegex(PolicyError,'unresolved'):request_for(self.store)
    def test_import_ack_keeps_provenance_and_does_not_claim_activation_verified(self):
        self.state['config']['legacy_imports']=[dict(kind='blacklist',rules_may_still_be_active=True)]
        r=request_for(self.store,legacy_ack=True)
        self.assertTrue(r['legacy_acknowledged']);self.assertEqual(len(r['legacy_imports']),1)
        self.assertFalse(r['plan']['activation_allowed']);self.assertFalse(r['plan']['no_leak_certified'])
    def test_empty_plan_refused(self):
        self.state['config']=new_config()
        with self.assertRaisesRegex(PolicyError,'no_rules'):request_for(self.store)
    def test_vpn_complement_plus_blacklist(self):
        self.state['config'].update(mode='vpn_allowlist',whitelist=['8.8.8.0/24'])
        r=request_for(self.store);self.assertEqual(len(r['plan']['rules']),3);self.assertEqual(len(r['plan']['overlaps']),1);self.assertFalse(r['plan']['activation_allowed'])
    def test_whitelist_only_no_programs(self):
        c=new_config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.8']);self.state['config']=c
        r=request_for(self.store);self.assertEqual(len(r['plan']['rules']),2);self.store.verified_programs.assert_not_called()
    def test_modified_executable_refused(self):
        self.store.verified_programs.side_effect=PolicyError('program_binary_changed_reselect_required')
        with self.assertRaisesRegex(PolicyError,'binary_changed'):request_for(self.store)
if __name__=='__main__':unittest.main()
