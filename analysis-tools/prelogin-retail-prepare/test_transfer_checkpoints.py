import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import transfer_probe as t
from test_transfer_probe import rcase, final, guard, response


class Checkpoints(unittest.TestCase):
 def run_case(self, status=200, raw_override=None, assert_before_read=None, assert_after_raw=None, assert_before_second=None):
  r=rcase();conn=Mock();res=response(final(),status)
  def read(_):
   saved=json.loads(Path('output/retail-transfer.json').read_text())
   if assert_before_read:assert_before_read(saved)
   return json.dumps(final()).encode() if raw_override is None else raw_override
  res.read.side_effect=read
  responses=[res,response({'installed':False,'downloaded_bytes':0}),response({'error':1})]
  conn.getresponse.side_effect=responses
  session=Mock(port=1234,token='PRIVATE_TOKEN');calls=[0]
  def verify():
   if Path('output/retail-transfer.json').is_file():
    saved=json.loads(Path('output/retail-transfer.json').read_text())
    if saved['finalization_response_bytes'] and not saved['finalized_returned'] and assert_after_raw:assert_after_raw(saved)
   return True
  def factory(*args,**kwargs):
   calls[0]+=1
   if calls[0]==2 and assert_before_second:
    assert_before_second(json.loads(Path('output/retail-transfer.json').read_text()))
   return conn
  session.verify.side_effect=verify;session.factory.side_effect=factory
  old=os.getcwd()
  with tempfile.TemporaryDirectory() as d:
   os.chdir(d);Path('output').mkdir()
   try:
    with patch.object(t.path_guard,'inspect',return_value=guard()),patch.object(t,'tcp_rows',return_value=[]),patch.object(t,'owner_at',return_value=321),patch.object(t,'connection_counts',return_value=t.counts()),patch.object(t,'file_snapshot',return_value={'files':0,'directories':0,'bytes':0}):
     t.execute(session,Path('D:/PRIVATE'),{'form':{'game_dir':{'game_dir':'D:/PRIVATE'}}},r)
    saved=json.loads(Path('output/retail-transfer.json').read_text())
   finally:os.chdir(old)
  return saved,calls[0]
 def test_headers_saved_before_body_read(self):
  seen=[]
  r,_=self.run_case(assert_before_read=lambda s:seen.append(s['finalization_http_status']))
  self.assertEqual(seen,[200])
 def test_raw_length_saved_before_post_identity_check(self):
  seen=[]
  self.run_case(assert_after_raw=lambda s:seen.append(s['finalization_response_bytes']))
  self.assertTrue(seen);self.assertGreater(seen[0],0)
 def test_parsed_finalization_saved_before_next_request(self):
  seen=[]
  self.run_case(assert_before_second=lambda s:seen.append((s['finalized_returned'],s['final_path_guard']['status'])))
  self.assertEqual(seen,[(True,'verified_existing_chain')])
 def test_http_error_keeps_status_and_never_starts(self):
  r,n=self.run_case(status=403)
  self.assertEqual(r['finalization_http_status'],403);self.assertEqual(n,1)
  self.assertFalse(r['start_attempted'])
 def test_bad_json_keeps_length_but_never_starts(self):
  r,n=self.run_case(raw_override=b'not json')
  self.assertEqual(r['finalization_response_bytes'],8);self.assertEqual(n,1)
  self.assertFalse(r['start_attempted']);self.assertIsNone(r['finalized_returned'])
 def test_checkpoints_export_no_payload(self):
  r,_=self.run_case()
  self.assertNotIn('PRIVATE',json.dumps(r));self.assertFalse(r['payload_exported'])

if __name__=='__main__':unittest.main()
