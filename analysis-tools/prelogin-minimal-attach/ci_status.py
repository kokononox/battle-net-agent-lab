"""Public CI outcomes only: never environment, private values, or raw logs."""
import json,re,sys
from pathlib import Path
OUTCOMES={'success','failure','cancelled','skipped','unknown'}
def status(source,run,phase,deps='unknown',tests='unknown',observe='unknown',sanitize='unknown'):
 if not re.fullmatch('[a-f0-9]{40}',source) or not re.fullmatch('[0-9]{1,30}',run):raise ValueError('identity')
 if phase not in {'dispatched','completed'} or not all(x in OUTCOMES for x in (deps,tests,observe,sanitize)):raise ValueError('enum')
 return dict(schema='bnet-minimal-attach-ci-1',source_commit=source,run_id=run,phase=phase,dependencies=deps,tests=tests,observation=observe,sanitization=sanitize)
if __name__=='__main__':
 dest=Path(sys.argv[1]);r=status(*sys.argv[2:]);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(r,indent=2)+'\n')
