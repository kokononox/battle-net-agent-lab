import unittest,os,tempfile
from pathlib import Path
from unittest.mock import patch
import preproduct_control as p
import report

class Control(unittest.TestCase):
 def test_fixed_claims(self):
  for k in ('finalization_requested','update_requested','account_parameter_sent','legal_acceptance_parameter_sent','global_limits_changed','all_agent_traffic_covered','game_payload_proven'):
   r=p.blank('a'*40,'1');r[k]=True
   with self.assertRaises(ValueError):p.validate(r)
 def test_zero_requests_not_boolean(self):
  for v in (1,True,-1,'0'):
   r=p.blank('a'*40,'1');r['product_api_requests']=v
   with self.assertRaises(ValueError):p.validate(r)
 def test_no_observed_without_evidence(self):
  r=p.blank('a'*40,'1');r['status']='observed'
  with self.assertRaises(ValueError):p.validate(r)
 def test_exact_fields(self):
  r=p.blank('a'*40,'1');r['raw_endpoint']='no'
  with self.assertRaises(ValueError):p.validate(r)
 def test_scope_before_work(self):
  with patch.dict(os.environ,{},clear=True),patch.object(p,'save')as save:
   with self.assertRaises(ValueError):p.execute(1,lambda:True,'a'*40,'1')
   save.assert_not_called()
 def test_wrong_identity_refuses_before_meter(self):
  env={'RETAIL_PREPRODUCT_CONTROL':'no-product-t7','RETAIL_PREPARE_SCOPE':'prepare-only-d11'}
  with patch.dict(os.environ,env,clear=True),patch.object(p,'save'),patch.object(p.meter_control,'start')as start:
   with self.assertRaises(ValueError):p.execute(1,lambda:False,'a'*40,'1')
   start.assert_not_called()
 def test_report_will_not_accept_product_mutation(self):
  r=report.blank('a'*40,'1');r['status']='preproduct_control_observed';r['transfer']['finalization_attempted']=True
  with self.assertRaises(ValueError):report.validate(r)
 def test_success_no_http_or_product_callbacks(self):
  from contextlib import ExitStack
  env={'RETAIL_PREPRODUCT_CONTROL':'no-product-t7','RETAIL_PREPARE_SCOPE':'prepare-only-d11'}
  m=dict(source_commit='a'*40,run_id='1',status='observing',baseline_ready=True,failed_reads=0,counter_resets=0)
  verify=unittest.mock.Mock(return_value=True)
  with ExitStack()as stack:
   stack.enter_context(patch.dict(os.environ,env,clear=True))
   save=stack.enter_context(patch.object(p,'save'))
   stack.enter_context(patch.object(p.transfer_probe,'tcp_rows',return_value=[]))
   stack.enter_context(patch.object(p.transfer_probe,'owner_at',return_value=123))
   stack.enter_context(patch.object(p.meter_control,'start',return_value='child'))
   stop=stack.enter_context(patch.object(p.meter_control,'stop'))
   stack.enter_context(patch.object(p.meter_receipt,'read',return_value=m))
   stack.enter_context(patch.object(p.time,'monotonic',side_effect=[0,.1,1.1]))
   stack.enter_context(patch.object(p.time,'sleep'))
   r=p.execute(1,verify,'a'*40,'1')
   self.assertEqual(r['status'],'observed');p.validate(r)
   self.assertEqual(verify.call_count,2);stop.assert_called_once_with('child')
 def test_callback_returns_before_session_or_product_request(self):
  import ast,run_prepare
  tree=ast.parse(Path(run_prepare.__file__).read_text())
  observer=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='observer')
  branch=next(n for n in ast.walk(observer)if isinstance(n,ast.If)and 'no-product-t7'in ast.unparse(n.test))
  self.assertIsInstance(branch.body[-1],ast.Return)
  self.assertLess(branch.lineno,next(n.lineno for n in ast.walk(observer)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='Session'))
 def test_report_empty_control(self):
  r=report.blank('a'*40,'1');r['status']='preproduct_control_observed';report.validate(r)
if __name__=='__main__':unittest.main()
