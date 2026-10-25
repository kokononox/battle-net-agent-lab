import base64,hashlib,json,unittest,zlib
import CollectReport as c
SHA='a'*40;RUN='123'
def report():return dict(schema='two_destination_setup_g25_v1',source_commit=SHA,run_id=RUN,scenario='real_setup',status='not_qualified',installation_verified=False,https_payload_classified=False)
def pack(r):
 raw=json.dumps(r,separators=(',',':')).encode();b=base64.b64encode(zlib.compress(raw)).decode();chunks=[b[i:i+600] for i in range(0,len(b),600)]
 return 'G25_REPORT_MANIFEST '+json.dumps(dict(parts=len(chunks),raw_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))+'\n'+'\n'.join(f'G25_REPORT_PART {i+1}/{len(chunks)} {v}' for i,v in enumerate(chunks))
class Tests(unittest.TestCase):
 def test_valid(self):self.assertEqual(c.extract(pack(report()),SHA,RUN)[1],report())
 def test_last_valid_checkpoint(self):
  a=report();b=report();b['status']='two_host_bootstrap_observed_restore_refused';self.assertEqual(c.extract(pack(a)+'\n'+pack(b),SHA,RUN)[1],b)
 def test_partial_later_checkpoint_preserves_earlier(self):self.assertEqual(c.extract(pack(report())+'\nG25_REPORT_MANIFEST {"parts":7}',SHA,RUN)[1],report())
 def test_wrong_source(self):
  with self.assertRaises(ValueError):c.extract(pack(report()),'b'*40,RUN)
 def test_wrong_run(self):
  with self.assertRaises(ValueError):c.extract(pack(report()),SHA,'456')
 def test_wrong_hash(self):
  with self.assertRaises(ValueError):c.extract(pack(report()).replace('G25_REPORT_PART 1/1 ','G25_REPORT_PART 1/1 A'),SHA,RUN)
 def test_unknown_field(self):
  r=report();r['raw_url']='secret'
  with self.assertRaises(ValueError):c.extract(pack(r),SHA,RUN)
 def test_raw_url_not_allowed_in_value(self):
  r=report();r['status']='https://example.org/?secret=x'
  with self.assertRaises(ValueError):c.extract(pack(r),SHA,RUN)
 def test_install_success_not_claimed(self):
  r=report();r['installation_verified']=True
  with self.assertRaises(ValueError):c.extract(pack(r),SHA,RUN)
 def test_duplicate_parts(self):
  t=pack(report());t+='\n'+t.splitlines()[-1]
  with self.assertRaises(ValueError):c.extract(t,SHA,RUN)
 def test_file_inventory_512(self):
  r=report();r['files_evidence']={'files':[{'sha256':'a'*64,'bytes':12} for _ in range(512)]};self.assertEqual(c.extract(pack(r),SHA,RUN)[1],r)
 def test_file_inventory_513_rejected(self):
  r=report();r['files_evidence']={'files':[{} for _ in range(513)]}
  with self.assertRaises(ValueError):c.extract(pack(r),SHA,RUN)
 def test_other_array_257_rejected(self):
  r=report();r['request_metadata']=[{} for _ in range(257)]
  with self.assertRaises(ValueError):c.extract(pack(r),SHA,RUN)
 def test_report_size_ceiling(self):
  self.assertEqual(c.MAX_REPORT,262144)
if __name__=='__main__':unittest.main()
