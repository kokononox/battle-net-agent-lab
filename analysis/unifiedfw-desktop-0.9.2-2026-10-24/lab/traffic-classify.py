from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from traffic_common import classify
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from state import atomic_json,assert_local_tree
p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--output',required=True);a=p.parse_args()
base=assert_local_tree(Path(__file__).resolve().parents[1]/'private-state/traffic-jobs').resolve()
req=assert_local_tree(a.request);out=assert_local_tree(a.output)
if base not in req.resolve().parents or base not in out.resolve().parents or req.parent!=out.parent:raise ValueError('classifier_path_scope')
if req.stat().st_size>4194304:raise ValueError('classifier_input_size')
atomic_json(out,classify(json.loads(req.read_text('utf-8-sig'))))
