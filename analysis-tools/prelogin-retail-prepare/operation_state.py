"""Fixed-field operation-resource state; no raw text, URLs, IDs or path values."""
import json,math
from pathlib import Path
import guard_report,response_diagnostic
FIELDS={'progress','download_complete','playable','installed','error','form','requires_authentication','needs_authentication','requires_login','requires_eula','eula_required','authentication','eula','min_spec','account_country','errors'}
BOOLS={'download_complete','playable','installed','requires_authentication','needs_authentication','requires_login','requires_eula','eula_required'}
REFUSALS=BOOLS-{'download_complete','playable','installed'}

def describe(data,resource):
 if type(data)is not dict or len(data)>128 or resource not in {'install','update','game'}:raise ValueError('operation_scope')
 value=data.get('progress');fraction=float(value)if type(value)in (int,float)and math.isfinite(value)and 0<=value<=1 else None
 error=data.get('error');error=error if type(error)is int and 0<=error<=2**32 else None
 flags={k:data.get(k)if type(data.get(k))is bool else None for k in sorted(BOOLS)}
 diagnostic=response_diagnostic.describe(data);markers=diagnostic['message_markers']
 refused=bool(set(markers)&{'authentication','legal','license','failure'})or any(flags[k]is True for k in REFUSALS)or 'error'in data and error!=0
 refused=refused or any(k in data and type(data[k])is not bool for k in REFUSALS)or any(k in data for k in ('authentication','eula','min_spec','account_country'))or bool(data.get('errors'))or any(n['numeric_code']not in (None,0)for n in diagnostic['nodes'])
 recognized=sorted(set(data)&FIELDS)
 return validate_state(dict(resource=resource,recognized_top_fields=recognized,unknown_top_fields=len(set(data)-FIELDS),progress_fraction=fraction,
    error_present='error'in data,error_code=error,form_present=type(data.get('form'))is dict,refusal_observed=refused,flags=flags))

def validate_state(s):
 if type(s)is not dict or set(s)!={'resource','recognized_top_fields','unknown_top_fields','progress_fraction','error_present','error_code','form_present','refusal_observed','flags'}or s['resource']not in {'install','update','game'}:raise ValueError('state_schema')
 if type(s['recognized_top_fields'])is not list or any(type(k)is not str or k not in FIELDS for k in s['recognized_top_fields'])or len(set(s['recognized_top_fields']))!=len(s['recognized_top_fields']):raise ValueError('fields')
 if type(s['unknown_top_fields'])is not int or not 0<=s['unknown_top_fields']<=128:raise ValueError('count')
 v=s['progress_fraction']
 if v is not None and(type(v)not in (int,float)or not math.isfinite(v)or not 0<=v<=1):raise ValueError('fraction')
 for k in ('error_present','form_present','refusal_observed'):
  if type(s[k])is not bool:raise ValueError('boolean')
 if s['error_code']is not None and(type(s['error_code'])is not int or not 0<=s['error_code']<=2**32):raise ValueError('error')
 if not s['error_present']and s['error_code']is not None:raise ValueError('absent_error')
 if type(s['flags'])is not dict or set(s['flags'])!=BOOLS or any(v is not None and type(v)is not bool for v in s['flags'].values()):raise ValueError('flags')
 return s

def eligible(s):
 validate_state(s)
 return s['resource']=='install'and not s['form_present']and not s['refusal_observed']and s['progress_fraction']is not None and s['progress_fraction']<1 and s['flags']['download_complete']is False and(not s['error_present']or s['error_code']==0)

def receipt(source,run,states):
 r=dict(schema='bnet-retail-operation-state-1',source_commit=source,run_id=run,states=states,account_parameter_sent=False,legal_acceptance_parameter_sent=False,payload_exported=False,raw_paths_exported=False,complete_installation_proven=False,game_payload_proven=False)
 return validate(r)
def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','states','account_parameter_sent','legal_acceptance_parameter_sent','payload_exported','raw_paths_exported','complete_installation_proven','game_payload_proven'}or r['schema']!='bnet-retail-operation-state-1':raise ValueError('schema')
 guard_report.identity(r)
 if type(r['states'])is not list or not 1<=len(r['states'])<=6:raise ValueError('states')
 for s in r['states']:validate_state(s)
 for k in set(r)-{'schema','source_commit','run_id','states'}:
  if r[k]is not False:raise ValueError('fixed')
 return r
def write(r):
 validate(r);p=Path('output/retail-operation-state.json');tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(r,indent=2)+'\n');tmp.replace(p)
if __name__=='__main__':
 import sys
 r=validate(guard_report.read(sys.argv[1]))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
