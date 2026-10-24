"""Allowlisted diagnostic counts only. Never substitute partial matches for evidence."""
import collections

def diagnose(events, packets, base, request_count):
    sends=base.socket_streams(events,'send')
    wire={r['key']:r['chunks'] for r in packets.get('runs',[])}
    groups=collections.defaultdict(list)
    for e in events:
        if e['kind']=='encrypt':groups[(e['pid'],e['context'])].append(e)
    result=[]
    for (pid,ctx),rows in groups.items():
        rows=sorted(rows,key=lambda e:e['order'])
        if any(e.get('return_code')!=0 or not e.get('complete') for e in rows):continue
        if any(a['sequence']>b['order'] for a,b in zip(rows,rows[1:])):continue
        plain=b''.join(e['before'] for e in rows)
        if len(plain)>base.LIMIT:continue
        reqs,_=base.requests(plain);offsets=[];pos=0
        for e in rows:offsets.append((pos,pos+len(e['before']),e));pos+=len(e['before'])
        for r in reqs:
            relevant=[e for a,b,e in offsets if a<r['stop'] and b>r['start']]
            records=[]
            for e in relevant:
                raw=e.get('after',b'');sm=base.locations(raw,sends);pm=base.locations(raw,wire)
                records.append({'socket_matches':len(sm),'socket_pid_match':len(sm)==1 and sm[0][0]==pid,
                    'packet_matches':len(pm),
                    'packet_prefix_matches':len(base.locations(raw[:32],wire)) if len(raw)>=32 else 0,
                    'packet_suffix_matches':len(base.locations(raw[-32:],wire)) if len(raw)>=32 else 0})
            result.append(records)
    if len(result)!=request_count:raise ValueError('diagnostic_request_alignment')
    return result
