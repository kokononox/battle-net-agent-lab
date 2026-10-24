import copy
import unittest
from unittest.mock import patch
from capture_policy import validate,configure,SCRIPT
class Policy(unittest.TestCase):
    def good(self):return dict(method='disable_netadapter_lso',adapter_count=1,previously_enabled_count=1,verified_disabled=True)
    def test_counts(self):validate(self.good())
    def test_unknown_key_rejected(self):
        p=self.good();p['private_adapter_name']='SECRET'
        with self.assertRaises(ValueError):validate(p)
    def test_unverified_rejected(self):
        p=self.good();p['verified_disabled']=False
        with self.assertRaises(ValueError):validate(p)
    def test_boolean_count_rejected(self):
        p=self.good();p['adapter_count']=True
        with self.assertRaises(ValueError):validate(p)
    def test_enabled_count_crossfoot(self):
        p=self.good();p['previously_enabled_count']=2
        with self.assertRaises(ValueError):validate(p)
    def test_no_security_changes(self):
        self.assertIn('Disable-NetAdapterLso',SCRIPT)
        for x in ('Set-NetFirewall','Disable-NetAdapterChecksumOffload','ExecutionPolicy','Set-MpPreference','-NoRestart'):self.assertNotIn(x,SCRIPT)
if __name__=='__main__':unittest.main()
