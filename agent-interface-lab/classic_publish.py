"""Separate strict-schema publisher for the two-request observation; never exports bodies."""
import json
import os
from pathlib import Path
import subprocess
import sys
import probe
import classic_install
import disk_prepare

def main():
    path=Path(sys.argv[1]);raw=path.read_bytes()
    if len(raw)>16384:raise ValueError('report_size')
    r=probe.unique_json(raw);classic_install.validate(r)
    if r['source_commit']!=os.environ['EXPECTED_SOURCE'] or r['run_id']!=os.environ['GITHUB_RUN_ID']:raise ValueError('report_identity')
    directory=Path('reports');directory.mkdir(exist_ok=True)
    paths=[directory/'classic-install-latest.json',directory/('classic-install-'+r['run_id']+'-1.json')]
    disk_path=path.with_name('classic-disk-to-share.json')
    disk_raw=disk_path.read_bytes()
    if len(disk_raw)>16384:raise ValueError('disk_report_size')
    disk=probe.unique_json(disk_raw);disk_prepare.validate(disk)
    for key in ('source_commit','run_id','run_attempt'):
        if disk[key]!=r[key]:raise ValueError('disk_report_identity')
    data=json.dumps(r,indent=2)+'\n'
    for target in paths:target.write_text(data,encoding='utf-8')
    disk_paths=[directory/'classic-disk-latest.json',directory/('classic-disk-'+r['run_id']+'-1.json')]
    for target in disk_paths:target.write_text(json.dumps(disk,indent=2)+'\n',encoding='utf-8')
    paths.extend(disk_paths)
    def git(*args):subprocess.run(['git',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    git('config','user.name','github-actions[bot]');git('config','user.email','41898282+github-actions[bot]@users.noreply.github.com')
    git('add','--',*[str(x) for x in paths])
    git('commit','-m','lab: publish sanitized Classic baseline observation '+r['run_id'])
    git('push','origin','HEAD:main') # No force/rebase over concurrent work.
    print(json.dumps({'sanitized_report_published':True,'status':r['status']}))
if __name__=='__main__':main()
