import unittest
from pathlib import Path
import meter_receipt as m
import meter_control as c

def good():
 r=dict(schema='bnet-owned-tcp-meter-1',source_commit='a'*40,run_id='1',status='observing',**m.FIXED)
 r.update({k:True for k in m.FLAGS});r.update({k:0 for k in m.NUMS});r['tracked_connections']=6;r['polls']=3;r['elapsed_ms']=50
 return r
class Meter(unittest.TestCase):
 def test_valid_checkpoint_not_full_coverage(self):
  r=m.validate(good());self.assertFalse(r['all_process_traffic_covered']);self.assertFalse(r['hardware_payload_proven'])
 def test_undefined_estats_cannot_be_accepted(self):
  for k in m.FLAGS:
   r=good();r[k]=False
   with self.assertRaises(ValueError):m.validate(r)
 def test_failed_read_not_valid_zero(self):
  for k in ('failed_reads','counter_resets','connection_set_changes','win32_error'):
   r=good();r[k]=1
   with self.assertRaises(ValueError):m.validate(r)
 def test_no_complete_or_hardware_or_payload_claim(self):
  for k in ('all_process_traffic_covered','hardware_payload_proven','raw_endpoints_exported','payload_exported','production_limits_changed'):
   r=good();r[k]=True
   with self.assertRaises(ValueError):m.validate(r)
 def test_no_arbitrary_identifiers(self):
  r=good();r['pid']=123
  with self.assertRaises(ValueError):m.validate(r)
 def test_no_bool_numeric_or_unbounded_counts(self):
  for k in m.NUMS:
   r=good();r[k]=True
   with self.assertRaises(ValueError):m.validate(r)
  for k,v in [('tracked_connections',129),('polls',201)]:
   r=good();r[k]=v
   with self.assertRaises(ValueError):m.validate(r)
 def test_cannot_launch_without_job_scope(self):
  from unittest.mock import patch
  with patch.dict(c.os.environ,{},clear=True):
   with self.assertRaises(ValueError):c.start(1,1)
 def launch_mock(self,ready_bytes):
  import tempfile,os,json
  from unittest.mock import patch,Mock
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir();Path('output/tcp_meter.exe').write_bytes(b'owned-test')
   process=Mock();process.poll.return_value=None
   def launch(*args,**kwargs):
    Path('output/tcp-meter-ready.signal').write_bytes(ready_bytes)
    Path('output/tcp-meter.json').write_text(json.dumps(good()))
    return process
   try:
    with patch.dict(c.os.environ,{'RETAIL_SUPERVISED':'job-c10','RETAIL_TCP_METER':'owned-baseline-t2','GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1'},clear=True),patch.object(c.subprocess,'Popen',side_effect=launch):
     if ready_bytes==b'ready\n':self.assertIs(c.start(123,1234),process);process.terminate.assert_not_called()
     else:
      with self.assertRaises(ValueError):c.start(123,1234)
      process.terminate.assert_called_once()
   finally:os.chdir(old)
 def test_exact_ready_protocol(self):self.launch_mock(b'ready\n')
 def test_translated_windows_newline_is_not_silently_accepted(self):self.launch_mock(b'ready\r\n')
 def test_native_ready_uses_binary_mode(self):
  s=Path(c.__file__).with_name('tcp_meter.cpp').read_text()
  self.assertIn('std::ofstream f("output/tcp-meter-ready.tmp",std::ios::binary)',s)
 def test_sdk_headers_and_environment_api(self):
  root=Path(c.__file__).parent
  h=(root/'estats_common.h').read_text();s=(root/'tcp_meter.cpp').read_text()
  self.assertIn('#include <ws2tcpip.h>',h);self.assertNotIn('getenv(',s);self.assertIn('GetEnvironmentVariableA',s)
 def test_native_keeps_process_handle_and_identity(self):
  s=Path(c.__file__).with_name('tcp_meter.cpp').read_text()
  for x in ('OpenProcess(SYNCHRONIZE','WaitForSingleObject(h,0)','r.dwOwningPid!=pid','listening==1','read_stats(v.row','now!=initial','Sleep(25)','k<200'):
   self.assertIn(x,s)
  self.assertNotIn('connect(',s);self.assertNotIn('CreateProcess',s)
if __name__=='__main__':unittest.main()
