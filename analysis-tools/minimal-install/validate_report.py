"""Strict sanitizer; no arbitrary paths or text are published in the report."""
import json,os,sys
from pathlib import Path
from model import validate

def decode(raw):
 if len(raw)>1048576:raise ValueError('report_size')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate_key')
   d[k]=v
  return d
 return validate(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique))

def main():
 source,destination=map(Path,sys.argv[1:3]);r=decode(source.read_bytes())
 if r['source_commit']!=os.environ['EXPECTED_SOURCE'] or r['run_id']!=os.environ['GITHUB_RUN_ID']:raise ValueError('unexpected_identity')
 if r['replica']!=os.environ['BNET_REPLICA']:raise ValueError('unexpected_replica')
 if r['status'] not in ('stopped','bounded_install_not_verified','installed_by_defined_gate') or (r['target_launched'] and r['ended_at'] is None):raise ValueError('unfinished_report')
 destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 print('Validated bounded sanitized C1b report')
if __name__=='__main__':main()
