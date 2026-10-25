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
 destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 print('Validated bounded sanitized C0 report')
if __name__=='__main__':main()
