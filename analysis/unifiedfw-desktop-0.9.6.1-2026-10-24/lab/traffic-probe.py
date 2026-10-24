"""One fresh child process / socket per trial. Never changes a Windows setting."""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from traffic_common import probe,endpoint
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from state import atomic_json,assert_local_tree

def main():
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    req=assert_local_tree(a.request);out=assert_local_tree(a.output)
    bases=[assert_local_tree(Path(__file__).resolve().parents[1]/('private-state/'+name)).resolve() for name in ('traffic-jobs','coexistence-jobs')]
    if not any(all(base in path.resolve().parents for path in (req,out)) for base in bases):raise ValueError('probe_job_path_escape')
    if req.parent!=out.parent or req.stat().st_size>8192:raise ValueError('probe_request_size_or_scope')
    q=json.loads(req.read_text('utf-8-sig'));endpoint(q['address'],q['port'])
    result=probe(q['address'],q['port'],q['challenge']);atomic_json(out,result)
    return 0
if __name__=='__main__':raise SystemExit(main())
