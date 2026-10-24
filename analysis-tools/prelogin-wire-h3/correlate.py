"""H2 remains frozen. Only successfully matched event-based completions normalize.
IOCP/callback/unmatched/ambiguous events remain barriers, never positive evidence.
"""
import importlib.util
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'prelogin-wire-h2'/'correlate.py'
spec=importlib.util.spec_from_file_location('_h2_correlate',p)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
def normalized(events):
    result=[]
    for e in events:
        x=dict(e)
        if x.get('asynchronous') is True and x.get('completion_proven') is True:
            x['asynchronous']=False
        result.append(x)
    return result
def socket_streams(events,kind):return base.socket_streams(normalized(events),kind)
def analyze(events,packets,classify=None):return base.analyze(normalized(events),packets,classify)
