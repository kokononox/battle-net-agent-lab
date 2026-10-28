"""Bounded baseline socket counters, never total-process or hardware proof."""
import json,re,sys
from pathlib import Path
FLAGS={'process_handle_held','listener_owner_verified','baseline_ready'}
NUMS={'win32_error','tracked_connections','polls','elapsed_ms','failed_reads','connection_set_changes','counter_resets','data_bytes_in_delta','data_bytes_out_delta','thru_bytes_received_delta','thru_bytes_acked_delta'}
FIXED=dict(scope='baseline_owned_external_ipv4_tcp_connections',window='pre_arm_baseline_to_last_checkpoint',all_process_traffic_covered=False,hardware_payload_proven=False,raw_endpoints_exported=False,payload_exported=False,production_limits_changed=False)
STATES={'not_started','owner_refused','enable_failed','read_failed','write_failed','observing','connection_set_changed','counter_reset','time_limit','completed','other','no_connections'}
def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','status'}|FLAGS|NUMS|set(FIXED)or r['schema']!='bnet-owned-tcp-meter-1':raise ValueError('schema')
 if type(r['source_commit'])is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit'])or type(r['run_id'])is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['status']not in STATES:raise ValueError('state')
 for k in FLAGS:
  if type(r[k])is not bool:raise ValueError('flag')
 for k,v in FIXED.items():
  if type(r[k])is not type(v)or r[k]!=v:raise ValueError('fixed')
 for k in NUMS:
  if type(r[k])is not int or not 0<=r[k]<=2**64-1:raise ValueError('number')
 if r['tracked_connections']>128 or r['polls']>200:raise ValueError('bounds')
 if r['baseline_ready']and(not all(r[k]for k in FLAGS)or not r['tracked_connections']):raise ValueError('baseline')
 if r['status']in {'observing','completed','time_limit'}and(not r['baseline_ready']or any(r[k]for k in ('win32_error','failed_reads','connection_set_changes','counter_resets'))):raise ValueError('observation')
 return r
def read(p):
 raw=Path(p).read_bytes()
 if len(raw)>8192:raise ValueError('size')
 def pairs(items):
  d={}
  for k,v in items:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 return validate(json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('constant'))))
if __name__=='__main__':
 r=read(sys.argv[1])
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('publish_identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
