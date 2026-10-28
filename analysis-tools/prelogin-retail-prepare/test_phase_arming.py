import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import guard_report as g
import transfer_probe as t
from test_guard_report import rec
from test_network_diagnostics import blank
from test_transfer_probe import rcase, guard

class Arming(unittest.TestCase):
 def test_ready_file(self):
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir();Path('output/retail-transfer-ready.signal').write_bytes(b'ready\n')
   try:self.assertTrue(t.await_arm())
   finally:os.chdir(old)
 def test_invalid_ready_refused(self):
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir();Path('output/retail-transfer-ready.signal').write_bytes(b'wrong\n')
   try:
    with self.assertRaises(ValueError):t.await_arm()
   finally:os.chdir(old)
 def test_timeout_refused(self):
  with patch.object(t.time,'monotonic',side_effect=[0,4]):
   with self.assertRaises(ValueError):t.await_arm()
 def test_refused_arm_never_sends(self):
  r=rcase();session=Mock(port=1234,token='PRIVATE');session.verify.return_value=True
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir()
   try:
    with patch.object(t,'await_arm',return_value=False),patch.object(t.path_guard,'inspect',return_value=guard()),patch.object(t,'tcp_rows',return_value=[]),patch.object(t,'owner_at',return_value=321),patch.object(t,'connection_counts',return_value=t.counts()),patch.object(t,'file_snapshot',return_value={'files':0,'directories':0,'bytes':0}):
     t.execute(session,Path('D:/PRIVATE'),{'form':{'game_dir':{'game_dir':'D:/PRIVATE'}}},r)
   finally:os.chdir(old)
  session.factory.assert_not_called();self.assertFalse(r['transfer']['finalization_attempted'])
  self.assertFalse(r['transfer']['phase_acknowledged'])
 def test_v2_request_requires_ack(self):
  r=t.blank('a'*40,'1');r.update(finalization_attempted=True,phase_signal_created=True,local_requests=1,preflight_path_guard=guard())
  with self.assertRaises(ValueError):t.validate(r)
  r['phase_acknowledged']=True;t.validate(r)
 def test_old_receipt_still_readable(self):
  r=t.blank('a'*40,'1');r['schema']='bnet-retail-transfer-1';r.pop('start_authorization');r.pop('phase_acknowledged');r.pop('finalization_response_shape');r.pop('response_diagnostic');r.pop('status_query_http_status');r.pop('status_query_response_bytes');t.validate(r)
 def test_new_native_receipt(self):
  r=rec('observe');r.update(schema='bnet-retail-supervisor-4',network_diagnostics=blank(),phase_arming_acknowledged=False,phase_baseline_policy='acknowledged_pre_request_snapshot');g.receipt(r)
  r['phase_arming_acknowledged']=True
  with self.assertRaises(ValueError):g.receipt(r)
 def test_native_ack_is_atomic_and_after_limit_checks(self):
  text=Path(t.__file__).with_name('guard.cpp').read_text()
  self.assertIn('MOVEFILE_WRITE_THROUGH',text)
  self.assertLess(text.index('if(r.delta>=r.byte_limit)'),text.index('!acknowledge()'))
  self.assertLess(text.index('if(elapsed>=r.time_limit)'),text.index('!acknowledge()'))
  self.assertIn('if(r.phase&&!arm.armed)',text)

if __name__=='__main__':unittest.main()
