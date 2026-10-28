"""Read-only post-finalization form state; no legal/account values or raw paths."""
import json,sys
from pathlib import Path
import guard_report
import retail_protocol
import path_guard,path_relation

def describe(data,target,source,run):
 s=retail_protocol.summarize(data)
 # Optional absent error is not an observed zero.
 if 'error'not in data:s['error_codes']['agent']=None
 f=data.get('form');form=f if type(f)is dict else {}
 finalized=form.get('finalized')if type(form.get('finalized'))is bool else None
 d=form.get('game_dir');returned=d.get('game_dir')if type(d)is dict else None
 r=dict(schema='bnet-retail-final-form-1',source_commit=source,run_id=run,
        status='observed',form_schema_valid=s['form_schema_valid'],form_fields=s['form_fields'],unknown_fields=s['unknown_fields'],error_codes=s['error_codes'],blockers=s['blockers'],
        finalized=finalized,eula_present='eula'in form,
        path_relation=path_relation.classify(str(target),returned),path_guard=path_guard.inspect(target,returned),
        query_resource='owned_install_wow',account_parameter_sent=False,legal_acceptance_parameter_sent=False,raw_response_exported=False,raw_paths_exported=False,download_proven=False)
 return validate(r)
def validate(r):
 keys={'schema','source_commit','run_id','status','form_schema_valid','form_fields','unknown_fields','error_codes','blockers','finalized','eula_present','path_relation','path_guard','query_resource','account_parameter_sent','legal_acceptance_parameter_sent','raw_response_exported','raw_paths_exported','download_proven'}
 if type(r)is not dict or set(r)!=keys or r['schema']!='bnet-retail-final-form-1'or r['status']!='observed'or r['query_resource']!='owned_install_wow':raise ValueError('schema')
 guard_report.identity(r)
 for k in ('form_schema_valid','unknown_fields','eula_present','account_parameter_sent','legal_acceptance_parameter_sent','raw_response_exported','raw_paths_exported','download_proven'):
  if type(r[k])is not bool or k in {'account_parameter_sent','legal_acceptance_parameter_sent','raw_response_exported','raw_paths_exported','download_proven'}and r[k]is not False:raise ValueError('flag')
 if type(r['form_fields'])is not list or len(set(r['form_fields']))!=len(r['form_fields'])or any(type(x)is not str or x not in retail_protocol.FIELDS for x in r['form_fields']):raise ValueError('fields')
 if type(r['blockers'])is not list or any(type(x)is not str or x not in retail_protocol.BLOCKERS for x in r['blockers']):raise ValueError('blockers')
 if type(r['error_codes'])is not dict or set(r['error_codes'])!={'agent',*retail_protocol.CODES}or any(v is not None and(type(v)is not int or not 0<=v<=2**32)for v in r['error_codes'].values()):raise ValueError('codes')
 if r['finalized']is not None and type(r['finalized'])is not bool:raise ValueError('finalized')
 path_guard.validate(r['path_guard']);path_relation.validate(r['path_relation'])
 if r['form_schema_valid']and(r['unknown_fields']or 'schema_invalid'in r['blockers']):raise ValueError('validity')
 return r
def write(r):
 validate(r);p=Path('output/retail-final-form.json');q=p.with_suffix('.tmp');q.write_text(json.dumps(r,indent=2)+'\n');q.replace(p)
if __name__=='__main__':
 r=validate(guard_report.read(sys.argv[1]))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
