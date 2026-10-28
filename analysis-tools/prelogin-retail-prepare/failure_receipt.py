"""Failure diagnostics: finite code labels only, never exception text/values."""
import json,sys
from pathlib import Path
import guard_report
STAGES={'preparation','before_request','finalization','start','status_query','content','snapshot','identity','polling','cleanup'}
REASONS={'tree_limit','tree_depth','tree_reparse','tree_type','tree_bytes','http','length','body_limit','transfer_scope','checkpoint_identity','checkpoint_resource','state_schema','states','content_watch_refused','watch_not_stopped','watch_scope','reference_changed','component','count','progress_object','progress_count','progress_fields','progress_counter','content_proof','source_changed','identity_changed','other'}
def make(source,run,stage,exc):
 name=type(exc).__name__;reason=exc.args[0]if len(exc.args)==1 and type(exc.args[0])is str else 'other'
 return validate(dict(schema='bnet-retail-failure-1',source_commit=source,run_id=run,stage=stage,exception_type=name if name in {'ValueError','OSError','Stop','RuntimeError'}else'other',reason=reason if reason in REASONS else'other',raw_exception_exported=False,payload_exported=False))
def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','stage','exception_type','reason','raw_exception_exported','payload_exported'}or r['schema']!='bnet-retail-failure-1':raise ValueError('schema')
 guard_report.identity(r)
 if r['stage']not in STAGES or r['reason']not in REASONS or r['exception_type']not in {'ValueError','OSError','Stop','RuntimeError','other'}or r['raw_exception_exported']is not False or r['payload_exported']is not False:raise ValueError('fields')
 return r
def write(r):
 validate(r);p=Path('output/retail-failure.tmp');p.write_text(json.dumps(r,indent=2)+'\n');p.replace('output/retail-failure.json')
if __name__=='__main__':
 r=validate(guard_report.read(sys.argv[1]))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
