"""One fixed-IP HTTPS attempt. No DNS, proxy, redirects or firewall operations."""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from https_common import probe_https,https_endpoint
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from state import atomic_json,assert_local_tree

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    req=assert_local_tree(args.request);out=assert_local_tree(args.output)
    base=assert_local_tree(Path(__file__).resolve().parents[1]/'private-state/coexistence-jobs').resolve()
    if any(base not in p.resolve().parents for p in (req,out)) or req.parent!=out.parent or req.stat().st_size>8192:raise ValueError('https_probe_request_scope_or_size')
    q=json.loads(req.read_text('utf-8-sig'));https_endpoint(q['https_url'],q['address'])
    if q['port']!=443:raise ValueError('https_exact_port_443_required')
    atomic_json(out,probe_https(q['https_url'],q['address'],q['challenge']));return 0
if __name__=='__main__':raise SystemExit(main())
