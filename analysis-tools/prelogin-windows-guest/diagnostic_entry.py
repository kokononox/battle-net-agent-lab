"""Bounded failure diagnosis; never exports exception text or tracebacks."""
import json,os,re,sys
from pathlib import Path
import prepare_guest as core
STAGES={'entry','guard','cleanup','apt','tool_version','download','extract_wim','xml_command','xml_parse','disk_create','qmp','validate','completed'}
KINDS={'none','ValueError','SystemExit','OSError','ProbeError','other'}
REASONS={'none','schema','source','run','status','limits','cleanup','number','boolean','version','image','media_hash','download','images','image_fields','edition','selection','disk','disk_size','qemu','ready_gate','guard_rejected','other'}
def validate(r):
 if not isinstance(r,dict) or set(r)!={'schema','source_commit','run_id','stage','exception_kind','reason','line','fallback_written'}:raise ValueError('diag_schema')
 if r['schema']!='bnet-preparation-diagnostic-1' or not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('diag_identity')
 if r['stage'] not in STAGES or r['exception_kind'] not in KINDS or r['reason'] not in REASONS or type(r['line']) is not int or not 0<=r['line']<=10000 or type(r['fallback_written']) is not bool:raise ValueError('diag_enum')
 return r
def run():
 source=os.environ['GITHUB_SHA'];run_id=os.environ['GITHUB_RUN_ID'];failed=False
 r=dict(schema='bnet-preparation-diagnostic-1',source_commit=source,run_id=run_id,stage='entry',exception_kind='none',reason='none',line=0,fallback_written=False)
 try:core.main();r['stage']='completed'
 except (Exception,SystemExit) as exc:
  failed=True;r['stage']=core.STAGE if core.STAGE in STAGES else 'entry';name=type(exc).__name__;r['exception_kind']=name if name in KINDS else 'other'
  reason=exc.args[0] if exc.args and isinstance(exc.args[0],str) else 'other'
  r['reason']=reason if reason in REASONS else ('guard_rejected' if isinstance(exc,SystemExit) and r['stage']=='guard' else 'other')
  tb=exc.__traceback__
  while tb:
   if tb.tb_frame.f_code.co_filename==core.__file__:r['line']=tb.tb_lineno
   tb=tb.tb_next
  # Never pretend the discarded, invalid partial result is valid.
  fallback=core.blank(source,run_id);fallback['error_code']='bounded_preparation_failed';core.validate(fallback)
  Path('output').mkdir(exist_ok=True);Path('output/windows-guest-preparation.json').write_text(json.dumps(fallback,indent=2)+'\n');r['fallback_written']=True
 validate(r);Path('output').mkdir(exist_ok=True);Path('output/windows-guest-preparation-diagnostic.json').write_text(json.dumps(r,indent=2)+'\n')
 return 1 if failed else 0
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));p=Path(sys.argv[3]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
 else:sys.exit(run())
