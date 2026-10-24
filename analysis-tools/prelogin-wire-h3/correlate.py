"""H2 remains frozen. Only matched event or registered Win32 callback completions normalize.
Other IOCP/callback, unmatched and ambiguous events remain barriers.
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
