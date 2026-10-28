import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import transfer_probe as t
import test_transfer_probe as fixtures
class OwnedOperation(unittest.TestCase):
 def run_case(self,state=None,start=None):
  r=fixtures.rcase();conn=Mock()
  queue={'progress':0.0,'download_complete':False,'playable':False}
  replies=[{'response_uri':'/install/wow','PRIVATE':'SECRET'},queue if state is None else state,{'response_uri':'/update/wow'}if start is None else start]+[dict(progress=.01*i,download_complete=False,playable=False)for i in range(1,5)]
  conn.getresponse.side_effect=[fixtures.response(d)for d in replies]
  session=Mock(port=1234,token='PRIVATE_TOKEN');session.verify.return_value=True;session.factory.return_value=conn
  old=os.getcwd();calls=[0]
  def snap(_):
   calls[0]+=1
   return dict(files=0,directories=0,bytes=0)if calls[0]==1 else dict(files=2,directories=2,bytes=174)
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir()
   try:
    with patch.dict(os.environ,{'RETAIL_START_OPERATION':'owned-install-t5'},clear=True),patch.object(t,'await_arm',return_value=True),patch.object(t.path_guard,'inspect',return_value=fixtures.guard()),patch.object(t,'tcp_rows',return_value=[]),patch.object(t,'owner_at',return_value=123),patch.object(t,'connection_counts',return_value=t.counts()),patch.object(t,'file_snapshot',side_effect=snap),patch.object(t.time,'sleep'):
     t.execute(session,Path('D:/PRIVATE'),{'form':{'game_dir':{'game_dir':'D:/PRIVATE'}}},r)
    result=json.loads(Path('output/retail-transfer.json').read_text());t.validate(result)
    operations=json.loads(Path('output/retail-operation-state.json').read_text())
   finally:os.chdir(old)
  return result,conn,operations
 def test_exact_owned_operation_can_start_without_faking_finalized_or_error(self):
  r,c,o=self.run_case();self.assertEqual(r['status'],'operation_start_observed');self.assertIsNone(r['finalized_returned']);self.assertIsNone(r['start_agent_error']);self.assertEqual(r['start_authorization'],'owned_install_operation');self.assertEqual(r['local_requests'],7);self.assertEqual(r['polls'],4)
  posts=[x for x in c.request.call_args_list if x.args[0]=='POST'];self.assertEqual([x.args[1]for x in posts],['/install/wow','/update']);self.assertEqual(json.loads(posts[1].kwargs['body']),{'uid':'wow'})
  self.assertFalse(r['complete_installation_proven']);self.assertFalse(o['game_payload_proven']);self.assertNotIn('PRIVATE',json.dumps(r))
 def test_explicit_login_stops_before_update(self):
  r,c,_=self.run_case({'progress':0.0,'download_complete':False,'requires_login':True});self.assertFalse(r['start_attempted']);self.assertEqual(c.request.call_count,2)
 def test_unknown_state_never_starts(self):
  r,c,_=self.run_case({});self.assertFalse(r['start_attempted']);self.assertEqual(c.request.call_count,2)
 def test_explicit_start_error_is_preserved_and_stops(self):
  r,c,_=self.run_case(start={'error':4});self.assertTrue(r['start_attempted']);self.assertEqual(r['start_agent_error'],4);self.assertEqual(r['status'],'start_refused');self.assertEqual(c.request.call_count,3)
if __name__=='__main__':unittest.main()
