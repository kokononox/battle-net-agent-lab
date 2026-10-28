"""Only fixed-label, source-bound calibration receipts; no endpoints or payloads."""
import json,re,sys
from pathlib import Path
FLAGS={'owner_verified','collection_enabled','control_collection_enabled','content_verified','control_unchanged'}
NUMS={'win32_error','application_received_bytes','application_sent_bytes','data_bytes_in_delta','data_bytes_out_delta','thru_bytes_received_delta','thru_bytes_acked_delta','hostwide_adapter_delta_bytes'}
FIXED=dict(loopback_only=True,external_transfer_requested=False,battle_net_launched=False,raw_endpoints_exported=False,payload_exported=False,production_limits_changed=False)
STATES={'not_started','socket_failed','owner_refused','enable_failed','read_failed','adapter_failed','transfer_failed','counter_decreased','calibrated','counter_mismatch','other'}
def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','status'}|FLAGS|NUMS|set(FIXED) or r['schema']!='bnet-tcp-fixture-1':raise ValueError('schema')
 if type(r['source_commit'])is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit'])or type(r['run_id'])is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if r['status']not in STATES:raise ValueError('status')
 for k in FLAGS|set(FIXED):
  if type(r[k])is not bool or k in FIXED and r[k]is not FIXED[k]:raise ValueError('flag')
 for k in NUMS:
  if type(r[k])is not int or not 0<=r[k]<=2**64-1:raise ValueError('number')
 if r['status']=='calibrated':
  if not all(r[k]for k in FLAGS)or r['win32_error']:raise ValueError('calibration_gate')
  for k in ('application_received_bytes','data_bytes_in_delta','thru_bytes_received_delta'):
   if r[k]!=1048576:raise ValueError('incoming')
  for k in ('application_sent_bytes','data_bytes_out_delta','thru_bytes_acked_delta'):
   if r[k]!=65536:raise ValueError('outgoing')
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
