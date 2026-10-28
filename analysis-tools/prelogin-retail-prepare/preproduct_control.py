"""Read-only observation after GET/agent, BEFORE any product API request.
No token, HTTP method, payload, filesystem target, or mutation callback is passed.
"""
import json,os,re,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'prelogin-tcp-attribution'))
import meter_control,meter_receipt
import transfer_probe

def blank(source,run):
 return dict(schema='bnet-preproduct-control-1',source_commit=source,run_id=run,status='pending',identity_verified_before=False,identity_verified_after=False,meter_started=False,meter_checkpoint_observed=False,product_api_requests=0,finalization_requested=False,update_requested=False,account_parameter_sent=False,legal_acceptance_parameter_sent=False,global_limits_changed=False,all_agent_traffic_covered=False,game_payload_proven=False,observation_limit_ms=1000)

def validate(r):
 if type(r)is not dict or set(r)!=set(blank('a'*40,'1'))or r['schema']!='bnet-preproduct-control-1':raise ValueError('schema')
 if type(r['source_commit'])is not str or re.fullmatch('[0-9a-f]{40}',r['source_commit'])is None or type(r['run_id'])is not str or re.fullmatch('[0-9]{1,30}',r['run_id'])is None:raise ValueError('identity')
 if r['status']not in {'pending','observing','observed','refused'}:raise ValueError('status')
 for k in ('identity_verified_before','identity_verified_after','meter_started','meter_checkpoint_observed'):
  if type(r[k])is not bool:raise ValueError('bool')
 for k in ('finalization_requested','update_requested','account_parameter_sent','legal_acceptance_parameter_sent','global_limits_changed','all_agent_traffic_covered','game_payload_proven'):
  if r[k]is not False:raise ValueError('fixed')
 if type(r['product_api_requests'])is not int or r['product_api_requests']!=0 or type(r['observation_limit_ms'])is not int or r['observation_limit_ms']!=1000:raise ValueError('limits')
 if r['meter_started']and not r['identity_verified_before']:raise ValueError('order')
 if r['identity_verified_after']and not r['meter_started']:raise ValueError('order')
 if r['status']=='observed'and not all(r[k]for k in ('identity_verified_before','identity_verified_after','meter_started','meter_checkpoint_observed')):raise ValueError('evidence')
 return r

def save(r):
 validate(r);p=Path('output/preproduct-control.tmp');p.write_text(json.dumps(r,indent=2)+'\n');p.replace('output/preproduct-control.json')

def execute(port,verify,source,run):
 if os.environ.get('RETAIL_PREPRODUCT_CONTROL')!='no-product-t7'or os.environ.get('RETAIL_PREPARE_SCOPE')!='prepare-only-d11'or os.environ.get('RETAIL_START_OPERATION')not in (None,'')or os.environ.get('RETAIL_PREARM_QUIET')not in (None,''):raise ValueError('scope')
 r=blank(source,run);save(r);meter=None
 try:
  if verify()is not True:raise ValueError('identity')
  r['identity_verified_before']=True;save(r)
  owner=transfer_probe.owner_at(port,transfer_probe.tcp_rows())
  meter=meter_control.start(owner,port);r['meter_started']=True;r['status']='observing';save(r)
  deadline=time.monotonic()+1
  while time.monotonic()<deadline:
   m=meter_receipt.read('output/tcp-meter.json')
   if m['source_commit']!=source or m['run_id']!=run or m['status']!='observing'or not m['baseline_ready']or m['failed_reads']or m['counter_resets']:raise ValueError('meter')
   r['meter_checkpoint_observed']=True;save(r);time.sleep(.1)
  if verify()is not True:raise ValueError('identity')
  r['identity_verified_after']=True;r['status']='observed';save(r)
 except Exception:
  r['status']='refused';save(r);raise
 finally:
  if meter is not None:meter_control.stop(meter)
 return r

if __name__=='__main__':
 r=validate(json.loads(Path(sys.argv[1]).read_text()))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
