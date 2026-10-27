import unittest,json,tempfile,os,socket,struct
from pathlib import Path
from unittest.mock import Mock,patch
import transfer_probe as t
import path_guard

def guard():return dict(status='verified_existing_chain',existing_components_checked=4,missing_tail=False,reparse_detected=False,absolute_containment_lexically_verified=True,race_free_containment_proven=False)
def final():
 return {'error':0,'form':{'authentication':{'error':0},'min_spec':{'error':0},'game_dir':{'error':0,'game_dir':'D:/PRIVATE'},'language':{'error':0},'eula':{'error':0,'eula':True},'tome_path':{'error':0},'finalized':True}}
def rcase():return dict(transfer=t.blank('a'*40,'1'),local_requests=3,form_update=dict(status='response_observed',response_finalized=False,response_schema_valid=True,response_error_codes=dict.fromkeys(('agent',*t.CODES),0),path_relation={'relation':'normalized_equal'}))
def response(d,status=200):
 r=Mock(status=status);r.getheader.side_effect=lambda k,v=None:v;r.read.return_value=json.dumps(d).encode();return r
class Transfer(unittest.TestCase):
 def test_blank(self):t.validate(t.blank('a'*40,'1'))
 def test_fixed_flags(self):
  for k in ('account_parameter_sent','country_parameter_sent','legal_acceptance_parameter_sent','complete_installation_proven','hardware_upload_proven'):
   r=t.blank('a'*40,'1');r[k]=True;self.assertRaises(ValueError,t.validate,r)
 def test_progress_redacted(self):
  r=t.progress({'installed':False,'PRIVATE':'SECRET','downloaded_bytes':512,'progress':{'downloaded':22,'PRIVATE':'SECRET'}});self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['counters'],{'downloaded_bytes':512,'progress.downloaded':22})
 def test_progress_bool_not_number(self):self.assertEqual(t.progress({'downloaded':True})['counters'],{})
 def test_file_metadata(self):
  with tempfile.TemporaryDirectory()as d:
   (Path(d)/'secret').write_bytes(b'abc');r=t.file_snapshot(d);self.assertEqual(r,{'files':1,'directories':0,'bytes':3});self.assertNotIn('secret',json.dumps(r))
 def test_symlink_refused(self):
  if os.name=='nt':self.skipTest('symlink privilege not required for CI')
  with tempfile.TemporaryDirectory()as d:
   (Path(d)/'x').symlink_to('/tmp');self.assertRaises(ValueError,t.file_snapshot,d)
 def test_owner_at(self):
  port=socket.htons(1234);rows=[(2,struct.unpack('=I',socket.inet_aton('127.0.0.1'))[0],port,0,0,321)];self.assertEqual(t.owner_at(1234,rows),321);self.assertRaises(ValueError,t.owner_at,1234,rows*2)
 def test_connections_scope(self):
  port=socket.htons(1234);local=struct.unpack('=I',socket.inet_aton('127.0.0.1'))[0];remote=struct.unpack('=I',socket.inet_aton('8.8.8.8'))[0]
  rows=[(2,local,port,0,0,321),(5,0,0,remote,socket.htons(443),321),(5,0,0,remote,socket.htons(80),999),(5,0,0,local,socket.htons(443),321)]
  r=t.connection_counts(1234,321,rows);self.assertEqual(r['443'],1);self.assertEqual(r['80'],0);self.assertRaises(ValueError,t.connection_counts,1234,999,rows)
 def simulate(self,final_response=None,start_response=None):
  r=rcase();conn=Mock();responses=[response(final_response or final()),response({'installed':False,'downloaded_bytes':0}),response(start_response or {'error':0})]+[response({'installed':False,'downloaded_bytes':i*100})for i in range(1,5)];conn.getresponse.side_effect=responses
  session=Mock(port=1234,token='PRIVATE_TOKEN');session.verify.return_value=True;session.factory.return_value=conn
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir()
   try:
    with patch.object(t,'await_arm',return_value=True),patch.object(t.path_guard,'inspect',return_value=guard()),patch.object(t,'tcp_rows',return_value=[]),patch.object(t,'owner_at',return_value=321),patch.object(t,'connection_counts',return_value=t.counts()),patch.object(t,'file_snapshot',return_value={'files':0,'directories':0,'bytes':0}),patch.object(t.time,'sleep'):
     t.execute(session,Path('D:/PRIVATE'),{'form':{'game_dir':{'game_dir':'D:/PRIVATE'}}},r)
    receipt=json.loads(Path('output/retail-transfer.json').read_text());t.validate(receipt)
   finally:os.chdir(old)
  return r,conn
 def test_bounded_happy_path(self):
  r,c=self.simulate();self.assertEqual(r['transfer']['status'],'observed');self.assertEqual(r['transfer']['polls'],4);self.assertEqual(r['transfer']['local_requests'],7);self.assertEqual(r['local_requests'],10)
  posts=[(call.args,json.loads(call.kwargs['body']))for call in c.request.call_args_list if call.args[0]=='POST'];self.assertEqual(posts[0][0],('POST','/install/wow'));self.assertIs(posts[0][1]['finalized'],True);self.assertEqual(posts[1],(('POST','/update'),{'uid':'wow'}));self.assertNotIn('PRIVATE',json.dumps(r));self.assertFalse(r['transfer']['hardware_upload_proven'])
 def test_auth_error_stops_before_start(self):
  d=final();d['form']['authentication']['error']=4;r,c=self.simulate(d);self.assertEqual(r['transfer']['status'],'finalization_refused');self.assertFalse(r['transfer']['start_attempted']);self.assertEqual(c.request.call_count,1)
 def test_unfinalized_stops(self):
  d=final();d['form']['finalized']=False;r,c=self.simulate(d);self.assertEqual(r['transfer']['status'],'finalization_refused');self.assertEqual(c.request.call_count,1)
 def test_start_error_no_polls(self):
  r,c=self.simulate(start_response={'error':42});self.assertEqual(r['transfer']['status'],'start_refused');self.assertEqual(r['transfer']['polls'],0);self.assertEqual(c.request.call_count,3)
if __name__=='__main__':unittest.main()
