import base64
import hashlib
import unittest
from samples import validate
class Tests(unittest.TestCase):
 def sample(self):
  b=b'{"cpu":"synthetic"}'
  return {'schema':'bnet-api-input-samples-1','source_commit':'a'*40,'run_id':'1','scope':'test_vm_no_account_user_authorized_buffer_values','reference':{'cpu_model':'Test CPU','windows_build':26100,'total_physical_memory_bytes':123456,'logical_processors':4},'samples':[{'pid':1,'process_sha256':'b'*64,'api':'EncryptMessage','context':'ctx1','sequence':1,'declared_length':len(b),'sample_truncated':False,'headers_redacted':False,'sample_sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()}],'limits':{'sample_bytes_limit':262144,'per_buffer_limit':16384,'server_receipt_proven':False,'user_pc_observed':False,'auth_cookie_headers_redacted':True}}
 def test_valid(self):validate(self.sample())
 def test_hash_failure(self):
  r=self.sample();r['samples'][0]['sample_sha256']='c'*64
  with self.assertRaises(ValueError):validate(r)
 def test_extra_path_rejected(self):
  r=self.sample();r['path']='secret'
  with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
