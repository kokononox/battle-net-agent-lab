"""H2 remains frozen. Only matched event or registered Win32 callback completions normalize.
Other IOCP/callback, unmatched and ambiguous events remain barriers.
"""
import importlib.util
import collections
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'prelogin-wire-h2'/'correlate.py'
spec=importlib.util.spec_from_file_location('_h2_correlate',p)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
def normalized(events):
    groups=collections.defaultdict(list)
    for e in events:
        if e.get('is_slice') is True:groups[(e.get('pid'),e.get('operation'))].append(e)
    valid=set()
    for key,rows in groups.items():
        rows=sorted(rows,key=lambda e:e.get('slice_offset',-1));offset=0;ok=True
        first=rows[0];total=first.get('operation_total_bytes')
        if type(total) is not int or not 131072<total<=67108864 or not isinstance(key[1],str):continue
        for i,e in enumerate(rows):
            n=e.get('accepted_bytes')
            if (e.get('kind')!='recv' or e.get('asynchronous') is not False or e.get('socket')!=first.get('socket')
                or e.get('order')!=first.get('order') or e.get('operation_total_bytes')!=total
                or type(e.get('slice_offset')) is not int or e['slice_offset']!=offset
                or type(n) is not int or not 0<n<=131072 or len(e.get('raw',b''))!=n
                or e.get('slice_final') is not (i==len(rows)-1) or e.get('complete') is not True):ok=False;break
            offset+=n
        if ok and offset==total:valid.add(key)
    result=[]
    for e in events:
        x=dict(e)
        if x.get('is_slice') is True and (x.get('pid'),x.get('operation')) not in valid:x['complete']=False
        if x.get('asynchronous') is True and x.get('completion_proven') is True:x['asynchronous']=False
        result.append(x)
    return result
def socket_streams(events,kind):return base.socket_streams(normalized(events),kind)
def analyze(events,packets,classify=None):return base.analyze(normalized(events),packets,classify)
