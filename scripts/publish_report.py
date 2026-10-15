"""Publish ONLY a schema-validated JSON from the separate clean reporting job."""
import json
import os
from pathlib import Path
import re
import subprocess
from validate_report import load

if __name__=='__main__':
    run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
    if not run.isdigit() or not attempt.isdigit():raise ValueError('invalid_run_identity')
    report=load(Path('incoming/agent-observation-to-share.json'))
    paths=[Path('reports/latest.json'),Path('reports/run-'+run+'-'+attempt+'.json')]
    for path in paths:
        path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    def git(*args):return subprocess.run(['git',*args],check=True)
    git('config','user.name','github-actions[bot]')
    git('config','user.email','41898282+github-actions[bot]@users.noreply.github.com')
    git('add','--',*(str(p) for p in paths))
    git('commit','-m','Record bounded Agent observation '+run+' attempt '+attempt)
    # Never force-push; concurrent branch changes must not be overwritten.
    git('push','origin','HEAD:main')
    summary=os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a',encoding='utf-8') as f:
            f.write('## Bounded Agent experiment\n\nStatus: `'+report['status']+'`\n\n')
            f.write('No login or game download was requested. Raw logs/binaries are not published.\n')
