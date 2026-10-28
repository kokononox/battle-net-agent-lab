"""Fixed-label receipt for censored metadata enumeration; not file absence proof."""
import json,sys
from pathlib import Path
import guard_report

def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','status','entry_limit_events','maximum_entries','file_absence_proven','raw_paths_exported'}or r['schema']!='bnet-retail-snapshot-status-1':raise ValueError('schema')
 guard_report.identity(r)
 if r['status']not in {'complete','entry_limit'}or type(r['entry_limit_events'])is not int or not 0<=r['entry_limit_events']<=32 or r['maximum_entries']!=512 or r['file_absence_proven']is not False or r['raw_paths_exported']is not False:raise ValueError('fields')
 if r['status']=='entry_limit'and not r['entry_limit_events']:raise ValueError('entry_limit')
 return r

def record(source,run,status):
 p=Path('output/retail-snapshot-status.json');n=0
 if p.exists():
  old=validate(guard_report.read(p))
  if(old['source_commit'],old['run_id'])!=(source,run):raise ValueError('identity')
  n=old['entry_limit_events']
 r=validate(dict(schema='bnet-retail-snapshot-status-1',source_commit=source,run_id=run,status=status,entry_limit_events=n+(status=='entry_limit'),maximum_entries=512,file_absence_proven=False,raw_paths_exported=False))
 tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(r,indent=2)+'\n');tmp.replace(p)
if __name__=='__main__':
 r=validate(guard_report.read(sys.argv[1]))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
