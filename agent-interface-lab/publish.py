"""Separate Linux reporter: validate the fixed schema, commit only sanitized JSON."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import probe

def main():
    path=Path(sys.argv[1]);raw=path.read_bytes()
    if len(raw)>16384:raise ValueError('report_size')
    r=probe.unique_json(raw);probe.validate(r)
    if r['source_commit']!=os.environ['EXPECTED_SOURCE'] or r['run_id']!=os.environ['GITHUB_RUN_ID']:raise ValueError('report_identity')
    directory=Path('reports');directory.mkdir(exist_ok=True)
    latest=directory/'agent-interface-latest.json'
    historical=directory/('agent-interface-'+r['run_id']+'-1.json')
    data=json.dumps(r,indent=2)+'\n'
    for target in (latest,historical):target.write_text(data,encoding='utf-8')
    def git(*args):subprocess.run(['git',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    git('config','user.name','github-actions[bot]');git('config','user.email','41898282+github-actions[bot]@users.noreply.github.com')
    git('add','--',str(latest),str(historical))
    git('commit','-m','lab: publish sanitized logged-out Agent interface observation '+r['run_id'])
    # Do not force/rebase over unrelated concurrent work. Failure is visible.
    git('push','origin','HEAD:main')
    print(json.dumps({'sanitized_report_published':True,'status':r['status']}))
if __name__=='__main__':main()
