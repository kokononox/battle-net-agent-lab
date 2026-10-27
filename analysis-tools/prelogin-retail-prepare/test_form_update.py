import unittest,json
from pathlib import Path
from unittest.mock import Mock
import form_update as u
import report
from retail_protocol import Session

def initial():
 return {'error':0,'form':{'authentication':{'error':0},'min_spec':{'error':0},'game_dir':{'error':800,'required_space':52000000000},'language':{'error':704,'list':['enUS'],'speech':['enUS'],'text':['enUS']},'eula':{'error':0,'eula':True},'finalized':False}}

def target(required,is_reparse,r):
 r.update(destination_guard_passed=True,minimum_free_required_bytes=required+10*1024**3,free_before_bytes=100*1024**3);return Path('D:/private-lab-target')
class Update(unittest.TestCase):
 def setup_case(self,data=None,verify=None):
  r=report.blank('a'*40,'1');r.update(local_requests=2,initialization_attempted=True,initial_summary_empty=True)
  response=Mock(status=200);response.getheader.side_effect=lambda k,d=None:d;response.read.return_value=json.dumps(data or initial()).encode()
  conn=Mock();conn.getresponse.return_value=response
  s=Session(1234,'secret-token',verify or Mock(return_value=True),r,Mock(return_value=conn))
  return r,s,conn,response
 def test_payload(self):
  p=u.payload(Path('D:/x'));self.assertIs(p['finalized'],False);self.assertEqual(set(p),{'finalized','game_dir','language','selected_asset_locale','selected_locale'});self.assertEqual(p['language'],['enUS'])
 def test_valid_prerequisites(self):self.assertEqual(u.prerequisites(initial()),52000000000)
 def test_prerequisite_guards(self):
  for section,key,val in [('authentication','error',1),('min_spec','error',1),('language','speech',[]),('game_dir','required_space',True)]:
   d=initial();d['form'][section][key]=val;self.assertRaises(ValueError,u.prerequisites,d)
  for v in (True,None,0):
   d=initial();d['form']['finalized']=v;self.assertRaises(ValueError,u.prerequisites,d)
 def test_update_once(self):
  r,s,c,_=self.setup_case();u.execute(s,initial(),r,lambda _:False,target);self.assertEqual(r['local_requests'],3);self.assertEqual(r['form_update']['status'],'response_observed');self.assertRaises(ValueError,u.execute,s,initial(),r,lambda _:False,target);self.assertEqual(c.request.call_count,1)
  args=c.request.call_args;self.assertEqual(args.args,('POST','/install/wow'));self.assertIs(json.loads(args.kwargs['body'])['finalized'],False)
 def test_no_private_export(self):
  r,s,*_=self.setup_case();u.execute(s,initial(),r,lambda _:False,target);text=json.dumps(r);self.assertNotIn('private-lab-target',text);self.assertNotIn('secret-token',text)
 def test_refuse_no_request(self):
  r,s,c,_=self.setup_case();d=initial();d['form']['finalized']=True;u.execute(s,d,r,lambda _:False,target);c.request.assert_not_called();self.assertEqual(r['form_update']['status'],'prerequisite_refused');u.validate(r['form_update'])
 def test_destination_failure(self):
  r,s,c,_=self.setup_case();u.execute(s,initial(),r,lambda _:False,Mock(side_effect=OSError('PRIVATE')));c.request.assert_not_called();self.assertEqual(r['form_update']['status'],'prerequisite_refused')
 def test_identity_before(self):
  r,s,c,_=self.setup_case(verify=lambda:False);u.execute(s,initial(),r,lambda _:False,target);c.request.assert_not_called();self.assertFalse(r['form_update']['attempted'])
 def test_identity_after(self):
  r,s,c,_=self.setup_case(verify=Mock(side_effect=[True,False]));u.execute(s,initial(),r,lambda _:False,target);self.assertEqual(r['form_update']['status'],'identity_changed')
 def test_unexpected_finalized(self):
  d=initial();d['form']['finalized']=True;r,s,*_=self.setup_case(d);u.execute(s,initial(),r,lambda _:False,target);self.assertEqual(r['form_update']['status'],'unexpected_finalized');u.validate(r['form_update'])
 def test_bad_http(self):
  r,s,c,response=self.setup_case();response.status=500;self.assertRaises(ValueError,u.execute,s,initial(),r,lambda _:False,target);c.close.assert_called_once();self.assertTrue(r['form_update']['attempted']);self.assertRaises(ValueError,u.execute,s,initial(),r,lambda _:False,target)
 def test_invalid_body(self):
  for raw in (b'[]',b'{"x":1,"x":2}',b'x'*65537):
   r,s,c,response=self.setup_case();response.read.return_value=raw;self.assertRaises(ValueError,u.execute,s,initial(),r,lambda _:False,target);c.close.assert_called_once()
 def test_validation(self):
  self.assertEqual(u.validate(u.blank()),u.blank())
  for k in ('attempted','destination_guard_passed'):
   r=u.blank();r[k]=1;self.assertRaises(ValueError,u.validate,r)
 def test_extra_request_report(self):
  r=report.blank('a'*40,'1');r['local_requests']=3;self.assertRaises(ValueError,report.validate,r)
if __name__=='__main__':unittest.main()
