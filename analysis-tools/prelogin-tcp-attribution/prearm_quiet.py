"""Bounded readiness heuristic BEFORE phase authorization; no network requests.

All bytes/time still count against the unchanged native GLOBAL guard. This is
not proof of total-process silence: it observes the meter's incomplete TCP scope.
"""
import json,os,time
from pathlib import Path
import meter_receipt

def validate(r):
 keys={'schema','source_commit','run_id','status','reads','quiet_intervals','required_quiet_intervals','interval_limit_bytes','wait_limit_ms','phase_request_sent','all_process_silence_proven','global_limits_changed'}
 if type(r)is not dict or set(r)!=keys or r['schema']!='bnet-prearm-quiet-1':raise ValueError('schema')
 import re
 if not re.fullmatch('[0-9a-f]{40}',r['source_commit'])or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['status']not in {'waiting','quiet_observed','timeout','meter_refused'}:raise ValueError('status')
 if type(r['reads'])is not int or not 0<=r['reads']<=12 or type(r['quiet_intervals'])is not int or not 0<=r['quiet_intervals']<=3:raise ValueError('counts')
 if r['required_quiet_intervals']!=3 or r['interval_limit_bytes']!=1048576 or r['wait_limit_ms']!=2500:raise ValueError('limits')
 if any(r[k]is not False for k in ('phase_request_sent','all_process_silence_proven','global_limits_changed')):raise ValueError('fixed')
 if r['status']=='quiet_observed'and r['quiet_intervals']!=3:raise ValueError('quiet')
 return r

def wait(source,run):
 r=dict(schema='bnet-prearm-quiet-1',source_commit=source,run_id=run,status='waiting',reads=0,quiet_intervals=0,required_quiet_intervals=3,interval_limit_bytes=1048576,wait_limit_ms=2500,phase_request_sent=False,all_process_silence_proven=False,global_limits_changed=False)
 def save():
  validate(r);p=Path('output/prearm-quiet.tmp');p.write_text(json.dumps(r,indent=2)+'\n');p.replace('output/prearm-quiet.json')
 save();deadline=time.monotonic()+2.5;previous=None
 try:
  while time.monotonic()<deadline and r['reads']<12:
   m=meter_receipt.read('output/tcp-meter.json');r['reads']+=1
   if m['source_commit']!=source or m['run_id']!=run or m['status']!='observing'or not m['baseline_ready']or m['failed_reads']or m['counter_resets']:raise ValueError('meter_not_observing')
   if previous is not None:
    gap=m['elapsed_ms']-previous['elapsed_ms'];delta=m['data_bytes_in_delta']+m['data_bytes_out_delta']-previous['data_bytes_in_delta']-previous['data_bytes_out_delta']
    fresh=0<gap<=500 and m['polls']>previous['polls']and m['connection_set_changes']==previous['connection_set_changes']
    r['quiet_intervals']=r['quiet_intervals']+1 if fresh and 0<=delta<=1048576 else 0
   previous=m;save()
   if r['quiet_intervals']>=3:r['status']='quiet_observed';save();return
   time.sleep(.25)
  r['status']='timeout';save();raise ValueError('prearm_not_quiet')
 except Exception:
  if r['status']=='waiting':r['status']='meter_refused';save()
  raise
if __name__=='__main__':
 import sys
 r=validate(json.loads(Path(sys.argv[1]).read_text()))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
