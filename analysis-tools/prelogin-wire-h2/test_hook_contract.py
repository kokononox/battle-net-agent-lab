"""Execute the actual JS descriptor selector in a stub VM; no target or network."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

@unittest.skipUnless(shutil.which('node'),'Node needed for actual JS call-contract checks')
class NativeContract(unittest.TestCase):
    def check_api(self,api,expected):
        source=Path(__file__).with_name('wire_hook.js')
        script='''const vm=require('vm'),fs=require('fs');
const c=vm.createContext({send(){},Process:{attachModuleObserver(){return {};}}});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);
const answer=vm.runInContext('messageDescriptor('+JSON.stringify(process.argv[2])+',[100,101,102,103])',c);
process.stdout.write(JSON.stringify(answer));'''
        p=subprocess.run(['node','-e',script,str(source),api],capture_output=True,timeout=10,check=True)
        self.assertEqual(json.loads(p.stdout),expected)
    def test_encrypt_descriptor_is_third_argument(self):self.check_api('EncryptMessage',102)
    def test_decrypt_descriptor_is_second_argument(self):self.check_api('DecryptMessage',101)

if __name__=='__main__':unittest.main()
