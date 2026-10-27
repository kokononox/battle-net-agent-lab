import unittest,json,copy
from unittest.mock import Mock
import retail_protocol as p
import report as r
from run_prepare import authorized,BRANCH

def form():
 return {'error':0,'form':{'authentication':{'error':0},'min_spec':{'error':2513},'game_dir':{'error':800},'eula':{'error':0,'eula':False}}}
class Protocol(unittest.TestCase):
 def make(self,raw=b'{}',status=200,headers=None,verify=None):
  response=Mock(status=status);response.getheader.side_effect=lambda k,d=None:(headers or {}).get(k,d);response.read.return_value=raw
  conn=Mock();conn.getresponse.return_value=response
  factory=Mock(return_value=conn);state=r.blank('a'*40,'1')
  return p.Session(1234,'private-token',verify or Mock(return_value=True),state,factory),state,conn,factory
 def test_payload_retail_only(self):
  d=p.initialized_payload();self.assertEqual(d['uid'],'wow');self.assertEqual(d['instructions_dataset'],['torrent','win','wow','enUS']);self.assertEqual(set(d),{'uid','instructions_dataset','instructions_patch_url','instructions_product','priority','monitor_pid'})
 def test_empty_summary_strict(self):
  for d in ({},{'error':0}):self.assertTrue(p.empty_summary(d))
  for d in ({'error':False},{'error':0.0},{'error':1},{'game':'private'},[]):self.assertFalse(p.empty_summary(d))
 def test_summary_then_init(self):
  s,state,c,f=self.make();self.assertEqual(s.request('GET','/game'),{});state['initial_summary_empty']=True;s.request('POST','/install');self.assertEqual(state['local_requests'],2);self.assertTrue(state['initialization_attempted']);self.assertEqual(f.call_args.args,('127.0.0.1',1234));self.assertEqual(c.request.call_args.args,('POST','/install'))
 def test_scope_rejections(self):
  for method,path in [('POST','/install/wow'),('GET','/agent'),('PUT','/install'),('GET','http://else/game')]:
   s,*_=self.make();self.assertRaises(ValueError,s.request,method,path)
 def test_init_requires_empty_summary(self):
  s,*_=self.make();self.assertRaises(ValueError,s.request,'POST','/install');s.request('GET','/game');self.assertRaises(ValueError,s.request,'POST','/install')
 def test_no_get_retry(self):
  s,*_=self.make(status=500);self.assertRaises(ValueError,s.request,'GET','/game');self.assertRaises(ValueError,s.request,'GET','/game')
 def test_no_post_retry_after_uncertainty(self):
  s,state,c,_=self.make();s.request('GET','/game');state['initial_summary_empty']=True;c.request.side_effect=OSError('private path');self.assertRaises(OSError,s.request,'POST','/install');self.assertRaises(ValueError,s.request,'POST','/install');self.assertEqual(state['local_requests'],2)
 def test_pre_identity(self):
  s,state,c,_=self.make(verify=lambda:False);self.assertRaises(ValueError,s.request,'GET','/game');c.request.assert_not_called();self.assertEqual(state['local_requests'],0)
 def test_post_identity(self):
  s,*_=self.make(verify=Mock(side_effect=[True,False]));self.assertRaises(ValueError,s.request,'GET','/game')
 def test_bad_response(self):
  for raw,status,h in [(b'{}',403,{}),(b'{}',200,{'Content-Encoding':'gzip'}),(b'{}',200,{'Content-Length':'65537'}),(b'{}',200,{'Content-Length':'3'}),(b'x'*65537,200,{}),(b'{"a":1,"a":2}',200,{}),(b'[]',200,{}),(b'{"a":NaN}',200,{})]:
   s,_,c,_=self.make(raw,status,h);self.assertRaises((ValueError,UnicodeError),s.request,'GET','/game');c.close.assert_called_once()
 def test_tokens_ports(self):
  for port,token in [(True,'x'),(0,'x'),(65536,'x'),(1,'a\nb'),(1,''),(1,'x'*8193)]:self.assertRaises(ValueError,p.Session,port,token,lambda:True,{})
 def test_form_blockers(self):
  d=p.summarize(form());self.assertTrue(d['form_schema_valid']);self.assertEqual(d['blockers'],['eula_review_pending','game_dir_error','minimum_spec_error']);self.assertEqual(d['error_codes']['authentication'],0)
 def test_form_no_private_values(self):
  d=form();d['form']['game_dir']['value']='PRIVATE_PATH';d['form']['eula']['text']='PRIVATE_LEGAL';self.assertNotIn('PRIVATE',json.dumps(p.summarize(d)))
 def test_unknown_field_not_exported(self):
  d=form();d['form']['PRIVATE_TOKEN']='SECRET';out=p.summarize(d);self.assertFalse(out['form_schema_valid']);self.assertNotIn('PRIVATE',json.dumps(out));self.assertNotIn('SECRET',json.dumps(out))
 def test_invalid_forms(self):
  for d in [{},{'form':[]},{'form':{}},{'error':False,'form':form()['form']},{'form':{'authentication':{'error':True}}}]:self.assertFalse(p.summarize(d)['form_schema_valid'])
 def test_legal_never_accepted(self):
  d=form();d['form']['eula']['eula']=True;self.assertIn('eula_review_pending',p.summarize(d)['blockers'])
 def test_metadata(self):
  raw=('Region!STRING:0|BuildConfig!HEX:16|VersionsName!STRING:0\neu|'+'a'*32+'|12.0.1.12345\n').encode();self.assertEqual(p.versions(raw)['version'],'12.0.1.12345');self.assertRaises(ValueError,p.versions,raw+raw.splitlines()[1]+b'\n')
 def test_metadata_bad(self):
  for raw in [b'',b'Region|Region\neu|eu',b'Region|BuildConfig|VersionsName\nus|abc|1.2.3.4',b'Region|BuildConfig|VersionsName\neu|abc|1.2.3.4',b'x'*(1024**2+1)]:self.assertRaises(ValueError,p.versions,raw)
class Reports(unittest.TestCase):
 def test_blank(self):self.assertEqual(r.load(json.dumps(r.blank('a'*40,'1')).encode())['status'],'not_started')
 def test_fixed_limits(self):
  for k in r.blank('a'*40,'1')['limits']:
   d=r.blank('a'*40,'1');d['limits'][k]=not d['limits'][k];self.assertRaises(ValueError,r.validate,d)
 def test_unknown_keys_private(self):
  d=r.blank('a'*40,'1');d['token']='SECRET';self.assertRaises(ValueError,r.validate,d)
 def test_positive_requires_evidence(self):
  for status in ('form_observed','form_schema_unknown'):
   d=r.blank('a'*40,'1');d['status']=status;self.assertRaises(ValueError,r.validate,d)
 def test_strict_numbers(self):
  for k in ('local_requests','identity_checks','initialization_response_bytes'):
   d=r.blank('a'*40,'1');d[k]=True;self.assertRaises(ValueError,r.validate,d)
 def test_legal_guard(self):
  d=r.blank('a'*40,'1');d['form']['form_fields']=['eula'];self.assertRaises(ValueError,r.validate,d)
 def test_source_bound(self):
  d=r.blank('a'*40,'1');d['handshake']['source_commit']='b'*40;self.assertRaises(ValueError,r.validate,d)
 def test_duplicate_json(self):self.assertRaises(ValueError,r.load,b'{"x":1,"x":2}')
 def test_auth_guard(self):
  e=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_REF=BRANCH,RETAIL_PREPARE='approved-retail-prepare-c9');self.assertTrue(authorized(e,'win32'));self.assertFalse(authorized(e,'linux'))
  for k in e:
   d=e.copy();d[k]='wrong';self.assertFalse(authorized(d,'win32'))
if __name__=='__main__':unittest.main()
